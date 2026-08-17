/**
 * Read-side masking for per-identity ACLs (feature/identity-acl).
 *
 * `maskEngineForRead(engine, hiddenPrefixes)` returns a BrainEngine view in
 * which every page whose slug falls under a hidden prefix behaves as if it
 * DOES NOT EXIST: direct fetches return the same null/empty shape a truly
 * nonexistent slug produces, and list/search/graph/chronicle surfaces simply
 * omit it. The op layer converts those shapes into the identical error
 * envelopes it produces for nonexistent slugs (e.g. get_page's
 * `page_not_found`), so a non-invited caller cannot distinguish "masked"
 * from "absent".
 *
 * WHERE IT IS APPLIED — the single choke point both MCP transports share:
 * `buildOperationContext` (src/mcp/dispatch.ts) swaps `ctx.engine` for this
 * view whenever the caller's `AuthInfo.hiddenSlugPrefixes` is non-empty.
 * That field is only ever populated by the Entra verification path
 * (src/core/entra-auth.ts) for NON-admin identities, so the exemptions are
 * structural, not conditional:
 *   - local CLI (no auth)              → raw engine
 *   - native OAuth / legacy tokens     → raw engine (owner-issued machine
 *     credentials; partners only ever get Entra sign-in)
 *   - admin-scoped Entra identities    → raw engine
 *   - non-admin Entra identities       → masked view for prefixes they are
 *     not invited to
 *
 * MATCHER REUSE: hidden prefixes use the exact grammar + boundary-aware
 * matcher of `oauth_clients.bound_slug_prefixes`
 * (`slugUnderBoundPrefixes` in operations.ts) — one matcher, one meaning.
 *
 * ENFORCEMENT SHAPE: interception is table-driven over the engine methods
 * remote read ops actually reach. Methods not listed pass through to the
 * raw engine — the write-side fence (enforceClientSlugFence + the dispatch
 * op allow-list) and the op-level executeRaw patches (extraction_pending,
 * schema_review_orphans, the entity card) cover the known bypasses; see
 * docs/entra-auth.md → "Identity ACL" for the caveat list.
 */

import type { BrainEngine } from './engine.ts';
import type { BrainStats } from './types.ts';
import { slugUnderBoundPrefixes, normalizeSlugPrefix } from './operations.ts';
import { escapeLikePattern } from './search/sql-ranking.ts';

/** Is `slug` under one of the caller's hidden prefixes? */
export function isSlugHidden(hidden: readonly string[], slug: string | null | undefined): boolean {
  if (slug === null || slug === undefined || slug === '') return false;
  return slugUnderBoundPrefixes(hidden, slug);
}

type AnyRow = Record<string, unknown>;

/** Every slug-shaped field a result row can reference. A row is dropped when ANY of them is hidden. */
function rowSlugs(row: AnyRow): string[] {
  const out: string[] = [];
  for (const key of [
    'slug', 'page_slug', 'from_slug', 'to_slug', 'origin_slug',
    'event_slug', 'entity_slug', 'last_event_slug',
  ]) {
    const v = row[key];
    if (typeof v === 'string' && v.length > 0) out.push(v);
  }
  return out;
}

function filterRows<T>(hidden: readonly string[], rows: T[]): T[] {
  return rows.filter(r => {
    if (r === null || typeof r !== 'object') return true;
    return !rowSlugs(r as AnyRow).some(s => isSlugHidden(hidden, s));
  });
}

/**
 * Wrap a BrainEngine so pages under `hidden` prefixes are indistinguishable
 * from nonexistent on every intercepted read path. `hidden` must be
 * non-empty (callers gate on that; an empty list returns the raw engine).
 */
export function maskEngineForRead(engine: BrainEngine, hidden: readonly string[]): BrainEngine {
  if (hidden.length === 0) return engine;
  const h = hidden;
  const hide = (slug: string | null | undefined) => isSlugHidden(h, slug);

  // Explicit override table. Each wrapper mimics the raw engine's
  // nonexistent-slug behavior for hidden inputs, and post-filters
  // hidden-slug rows out of list results.
  const overrides: Partial<Record<keyof BrainEngine, (...args: never[]) => unknown>> = {
    // ── direct fetch by slug: behave exactly like a missing row ─────────
    getPage: async (slug: string, opts?: object) =>
      hide(slug) ? null : engine.getPage(slug, opts as never),
    getChunks: async (slug: string, opts?: object) =>
      hide(slug) ? [] : engine.getChunks(slug, opts as never),
    getChunksWithEmbeddings: async (slug: string, opts?: object) =>
      hide(slug) ? [] : engine.getChunksWithEmbeddings(slug, opts as never),
    getTags: async (slug: string, opts?: object) =>
      hide(slug) ? [] : engine.getTags(slug, opts as never),
    getTimeline: async (slug: string, opts?: object) =>
      hide(slug) ? [] : engine.getTimeline(slug, opts as never),
    getVersions: async (slug: string, opts?: object) =>
      hide(slug) ? [] : engine.getVersions(slug, opts as never),
    getRawData: async (slug: string, source?: string, opts?: object) =>
      hide(slug) ? [] : engine.getRawData(slug, source, opts as never),
    getOntology: async (slug: string, opts?: object) =>
      hide(slug) ? [] : engine.getOntology(slug, opts as never),
    getLinks: async (slug: string, opts?: object) =>
      hide(slug) ? [] : filterRows(h, await engine.getLinks(slug, opts as never)),
    getBacklinks: async (slug: string, opts?: object) =>
      hide(slug) ? [] : filterRows(h, await engine.getBacklinks(slug, opts as never)),
    getLastSeen: async (entitySlug: string, opts?: object) => {
      if (hide(entitySlug)) {
        // Same shape the engine returns for an entity with no timeline hits.
        return { entity_slug: entitySlug, last_date: null, last_event_slug: null, days_ago: null };
      }
      const res = await engine.getLastSeen(entitySlug, opts as never);
      // The last event involving a visible entity may itself be hidden;
      // redact the event slug (the date alone names no page).
      return res && hide((res as unknown as AnyRow).last_event_slug as string | undefined)
        ? { ...res, last_event_slug: null }
        : res;
    },

    // ── search ──────────────────────────────────────────────────────────
    searchKeyword: async (q: string, opts?: object) =>
      filterRows(h, await engine.searchKeyword(q, opts as never)),
    searchTitles: async (q: string, opts?: object) =>
      filterRows(h, await engine.searchTitles(q, opts as never)),
    searchVector: async (e: Float32Array, opts?: object) =>
      filterRows(h, await engine.searchVector(e, opts as never)),
    searchKeywordChunks: async (q: string, opts?: object) =>
      filterRows(h, await engine.searchKeywordChunks(q, opts as never)),
    findByTitleFuzzy: async (name: string, dirPrefix?: string, minSim?: number, sourceId?: string) => {
      const res = await engine.findByTitleFuzzy(name, dirPrefix, minSim, sourceId);
      return res && hide(res.slug) ? null : res;
    },

    // ── slug enumeration / resolution ───────────────────────────────────
    listPages: async (filters?: object) =>
      filterRows(h, await engine.listPages(filters as never)),
    resolveSlugs: async (partial: string, opts?: object) =>
      (await engine.resolveSlugs(partial, opts as never)).filter(s => !hide(s)),
    getAllSlugs: async (opts?: object) => {
      const set = await engine.getAllSlugs(opts as never);
      return new Set([...set].filter(s => !hide(s)));
    },
    listAllPageRefs: async () => filterRows(h, await engine.listAllPageRefs()),
    resolveSlugsByPaths: async (paths: string[], opts: object) => {
      const map = await engine.resolveSlugsByPaths(paths, opts as never);
      for (const [k, v] of map) if (hide(v)) map.delete(k);
      return map;
    },
    resolveSlugWithAlias: async (slug: string, sourceOrSources: string | readonly string[]) => {
      // A hidden input or a hidden resolution target both behave like
      // "no alias found": the input comes back unchanged.
      if (hide(slug)) return slug;
      const resolved = await engine.resolveSlugWithAlias(slug, sourceOrSources as never);
      return hide(resolved) ? slug : resolved;
    },
    resolveAliases: async (aliasNorms: string[], opts?: object) => {
      const map = await engine.resolveAliases(aliasNorms, opts as never);
      for (const [k, v] of map) {
        const kept = v.filter(entry => !hide(entry.slug));
        if (kept.length === 0) map.delete(k);
        else map.set(k, kept);
      }
      return map;
    },
    listPrefixSampledPages: async (opts: object) =>
      filterRows(h, await engine.listPrefixSampledPages(opts as never)),
    listCorpusSample: async (opts: object) =>
      filterRows(h, await engine.listCorpusSample(opts as never)),

    // ── batch slug-keyed lookups: strip hidden INPUTS so no result key can
    //    reference a hidden page regardless of the engine's key format ────
    getBacklinkCounts: async (slugs: string[]) => {
      const visible = slugs.filter(s => !hide(s));
      const map = visible.length > 0 ? await engine.getBacklinkCounts(visible) : new Map<string, number>();
      // Contract: every input slug is present (0 for no inbound links) —
      // identical to how a nonexistent slug reads.
      for (const s of slugs) if (hide(s)) map.set(s, 0);
      return map;
    },
    getPageTimestamps: async (slugs: string[]) =>
      engine.getPageTimestamps(slugs.filter(s => !hide(s))),
    getEffectiveDates: async (refs: Array<{ slug: string; source_id: string }>) =>
      engine.getEffectiveDates(refs.filter(r => !hide(r.slug))),
    getSalienceScores: async (refs: Array<{ slug: string; source_id: string }>) =>
      engine.getSalienceScores(refs.filter(r => !hide(r.slug))),

    // ── graph ───────────────────────────────────────────────────────────
    traverseGraph: async (slug: string, depth?: number, opts?: object) => {
      if (hide(slug)) return [];
      const nodes = filterRows(h, await engine.traverseGraph(slug, depth, opts as never));
      // Strip edges pointing INTO hidden pages from surviving nodes.
      return nodes.map(n => ({
        ...n,
        links: (n.links ?? []).filter(l => !hide(l.to_slug)),
      }));
    },
    traversePaths: async (slug: string, opts?: object) =>
      hide(slug) ? [] : filterRows(h, await engine.traversePaths(slug, opts as never)),
    relationalFanout: async (seeds: string[], opts?: object) => {
      const visibleSeeds = seeds.filter(s => !hide(s));
      if (visibleSeeds.length === 0) return [];
      const rows = await engine.relationalFanout(visibleSeeds, opts as never);
      // Drop nodes that are hidden OR whose connecting path names a hidden page.
      return rows.filter(r => !hide(r.slug) && !r.path.some(p => hide(p)));
    },
    listLinkSources: async (opts?: object) => engine.listLinkSources(opts as never),

    // ── chronicle / timeline projections ────────────────────────────────
    getTimelineForDate: async (date: string, opts?: object) =>
      filterRows(h, await engine.getTimelineForDate(date, opts as never)),
    getSince: async (date: string, opts?: object) =>
      filterRows(h, await engine.getSince(date, opts as never)),
    getOnThisDay: async (opts?: object) =>
      filterRows(h, await engine.getOnThisDay(opts as never)),
    getRecentSalience: async (opts: object) =>
      filterRows(h, await engine.getRecentSalience(opts as never)),

    // ── audits / discovery ──────────────────────────────────────────────
    findOrphanPages: async (opts?: object) =>
      filterRows(h, await engine.findOrphanPages(opts as never)),
    findAnomalies: async (opts: object) => {
      const rows = await engine.findAnomalies(opts as never);
      // Cohort statistics stay as computed (documented caveat); the slug
      // LISTS are scrubbed so no hidden page is ever named.
      return rows.map(r => ({ ...r, page_slugs: r.page_slugs.filter(s => !hide(s)) }));
    },
    getIngestLog: async (opts?: object) => {
      const rows = await engine.getIngestLog(opts as never);
      return rows
        .map(r => ({ ...r, pages_updated: r.pages_updated.filter(s => !hide(s)) }))
        // An entry whose every page is hidden is omitted entirely — its
        // summary text could otherwise describe hidden content.
        .filter((r, i) => r.pages_updated.length > 0 || rows[i].pages_updated.length === 0);
    },

    // ── takes ───────────────────────────────────────────────────────────
    listTakes: async (opts?: object) => filterRows(h, await engine.listTakes(opts as never)),
    listStaleTakes: async () => filterRows(h, await engine.listStaleTakes()),
    searchTakes: async (q: string, opts?: object) =>
      filterRows(h, await engine.searchTakes(q, opts as never)),
    searchTakesVector: async (...args: unknown[]) =>
      filterRows(h, await (engine.searchTakesVector as unknown as (...a: unknown[]) => Promise<AnyRow[]>)(...args)),

    // ── facts / trajectory ──────────────────────────────────────────────
    listFactsByEntity: async (sourceId: string, entitySlug: string, opts?: object) =>
      hide(entitySlug) ? [] : filterRows(h, await engine.listFactsByEntity(sourceId, entitySlug, opts as never)),
    listFactsSince: async (sourceId: string, since: Date, opts?: object) =>
      filterRows(h, await engine.listFactsSince(sourceId, since, opts as never)),
    listFactsBySession: async (sourceId: string, sessionId: string, opts?: object) =>
      filterRows(h, await engine.listFactsBySession(sourceId, sessionId, opts as never)),
    findTrajectory: async (opts: { entitySlug: string }) =>
      hide(opts.entitySlug) ? [] : engine.findTrajectory(opts as never),

    // ── stats: subtract hidden pages/chunks so totals do not reveal
    //    existence. Link/tag/timeline totals keep raw values (documented
    //    caveat — see docs/entra-auth.md). Fail-open on schema drift:
    //    comparative count inference is strictly weaker than a hard error
    //    surface that itself signals "something here is special". ─────────
    getStats: async (): Promise<BrainStats> => {
      const raw = await engine.getStats();
      try {
        const likeParams = h.map(p => `${escapeLikePattern(normalizeSlugPrefix(p))}%`);
        const likeClause = likeParams
          .map((_, i) => `p.slug LIKE $${i + 1} ESCAPE '\\'`)
          .join(' OR ');
        const rows = await engine.executeRaw<{ type: string; pages: number | string; chunks: number | string; embedded: number | string }>(
          `SELECT p.type AS type,
                  count(*)::int AS pages,
                  coalesce(sum(c.n), 0)::int AS chunks,
                  coalesce(sum(c.e), 0)::int AS embedded
             FROM pages p
             LEFT JOIN LATERAL (
               SELECT count(*) AS n,
                      count(*) FILTER (WHERE cc.embedded_at IS NOT NULL) AS e
                 FROM content_chunks cc WHERE cc.page_id = p.id
             ) c ON true
            WHERE p.deleted_at IS NULL AND (${likeClause})
            GROUP BY p.type`,
          likeParams,
        );
        let hiddenPages = 0, hiddenChunks = 0, hiddenEmbedded = 0;
        const byType: Record<string, number> = { ...raw.pages_by_type };
        for (const r of rows) {
          const pages = Number(r.pages);
          hiddenPages += pages;
          hiddenChunks += Number(r.chunks);
          hiddenEmbedded += Number(r.embedded);
          if (r.type in byType) {
            byType[r.type] = Math.max(0, byType[r.type] - pages);
            if (byType[r.type] === 0) delete byType[r.type];
          }
        }
        return {
          ...raw,
          page_count: Math.max(0, raw.page_count - hiddenPages),
          chunk_count: Math.max(0, raw.chunk_count - hiddenChunks),
          embedded_count: Math.max(0, raw.embedded_count - hiddenEmbedded),
          pages_by_type: byType,
        };
      } catch {
        return raw;
      }
    },
  };

  return new Proxy(engine, {
    get(target, prop, receiver) {
      const override = overrides[prop as keyof BrainEngine];
      if (override) return override;
      void receiver;
      const value = Reflect.get(target, prop);
      // Bind methods to the RAW engine so internal `this.` calls keep their
      // original semantics (the mask applies at the op boundary, once).
      return typeof value === 'function' ? (value as (...a: unknown[]) => unknown).bind(target) : value;
    },
  }) as BrainEngine;
}
