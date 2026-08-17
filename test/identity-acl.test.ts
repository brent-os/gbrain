/**
 * feature/identity-acl — per-identity read-masking + write-fencing.
 *
 * Three layers under test, end to end:
 *  1. Config → AuthInfo: real Entra JWTs (local RSA keypair, no network)
 *     verified by verifyEntraToken produce boundSlugPrefixes (write fence)
 *     and hiddenSlugPrefixes (read mask).
 *  2. Dispatch: dispatchToolCall (the choke point both MCP transports share)
 *     swaps ctx.engine for the masked view and applies the fail-closed op
 *     allow-list.
 *  3. Ops against a scratch PGLite brain: pages inside + outside a masked
 *     prefix; a NON-INVITED identity must find the masked pages
 *     indistinguishable from nonexistent (direct-fetch error envelopes
 *     captured BEFORE the pages exist and compared byte-for-byte after);
 *     an INVITED identity and a legacy token client get full visibility;
 *     the write fence accepts in-prefix and rejects out-of-prefix +
 *     masked-without-invite writes.
 *
 * The adversarial ordering matters: read tests run before write tests so
 * stats/count assertions see a stable page set (bun runs a file's tests in
 * declaration order).
 */

import { describe, test, expect, beforeAll, afterAll, setDefaultTimeout } from 'bun:test';
import { generateKeyPair, SignJWT } from 'jose';
import { PGLiteEngine } from '../src/core/pglite-engine.ts';
import { resetGateway } from '../src/core/ai/gateway.ts';
import { dispatchToolCall } from '../src/mcp/dispatch.ts';
import { verifyEntraToken, type EntraConfig } from '../src/core/entra-auth.ts';
import type { AuthInfo } from '../src/core/operations.ts';
import type { BrainEngine } from '../src/core/engine.ts';
import { isSlugHidden, maskEngineForRead } from '../src/core/read-mask.ts';

// The beforeAll does a full PGLite schema init (120+ migrations) plus RSA
// keygen and fixture writes; under the parallel loop's shared-process
// contention that exceeds the 5s default hook budget.
setDefaultTimeout(60_000);

const TENANT = '00000000-1111-2222-3333-444444444444';
const CLIENT = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
const V2_ISSUER = `https://login.microsoftonline.com/${TENANT}/v2.0`;

let engine: PGLiteEngine;

// Verified AuthInfo per identity (minted once from real signed JWTs).
let aliceAuth: AuthInfo;   // read+write, fenced to partners/alice/, NOT invited
let carolAuth: AuthInfo;   // read+write, unfenced, NOT invited (masked writer case)
let bobAuth: AuthInfo;     // read+write, fenced to partners/bob/ + restricted/, INVITED
let ownerAuth: AuthInfo;   // read+write+admin → exempt from masking
const legacyAuth: AuthInfo = {
  // Hand-built legacy bearer shape: no `entra`, no hiddenSlugPrefixes —
  // exactly what oauth-provider's verifyAccessToken produces. Full visibility.
  token: 'gbrain_legacy_test',
  clientId: 'legacy-machine-token',
  clientName: 'legacy-machine-token',
  scopes: ['read', 'write', 'admin'],
};

function entraCfg(): EntraConfig {
  return {
    tenantId: TENANT,
    clientId: CLIENT,
    clientSecret: 's',
    apiScope: `api://${CLIENT}/access`,
    acceptV1Issuer: false,
    identityMap: new Map([
      ['alice@build.test', { scopes: ['read', 'write'], writePrefixes: ['partners/alice/'] }],
      ['carol@build.test', { scopes: ['read', 'write'] }],
      ['bob@build.test', { scopes: ['read', 'write'], writePrefixes: ['partners/bob/', 'restricted/'] }],
      ['owner@build.test', { scopes: ['read', 'write', 'admin'] }],
    ]),
    defaultScopes: [],
    maskedPrefixes: new Map([['restricted/', ['bob@build.test']]]),
  };
}

/** Dispatch a tool call. auth === undefined → trusted local (setup path). */
async function call(name: string, params: Record<string, unknown>, auth?: AuthInfo) {
  const r = await dispatchToolCall(engine, name, params, {
    remote: auth !== undefined,
    sourceId: 'default',
    ...(auth ? { auth } : {}),
  });
  return { isError: r.isError === true, body: JSON.parse(r.content[0].text) as Record<string, unknown> };
}

const MASKED_A = 'restricted/summary';
const MASKED_B = 'restricted/case-x/file';

// Error envelopes for the masked slugs captured while they GENUINELY did not
// exist — the equality oracle for existence-hiding.
const nonexistentEnvelopes = new Map<string, unknown>();
const READ_BY_SLUG_OPS: Array<[string, (slug: string) => Record<string, unknown>]> = [
  ['get_page', (slug) => ({ slug })],
  ['get_chunks', (slug) => ({ slug })],
  ['get_tags', (slug) => ({ slug })],
  ['get_timeline', (slug) => ({ slug })],
  ['get_links', (slug) => ({ slug })],
  ['get_backlinks', (slug) => ({ slug })],
  ['get_versions', (slug) => ({ slug })],
  ['get_raw_data', (slug) => ({ slug })],
  ['traverse_graph', (slug) => ({ slug })],
];

beforeAll(async () => {
  engine = new PGLiteEngine();
  await engine.connect({});
  await engine.initSchema();
  resetGateway(); // no embedding provider — keyword-only retrieval, no network

  const { privateKey, publicKey } = await generateKeyPair('RS256');
  const mint = async (upn: string, oid: string): Promise<AuthInfo> => {
    const jwt = await new SignJWT({ preferred_username: upn, oid, tid: TENANT })
      .setProtectedHeader({ alg: 'RS256' })
      .setIssuer(V2_ISSUER)
      .setAudience(CLIENT)
      .setIssuedAt()
      .setExpirationTime('1h')
      .sign(privateKey);
    return verifyEntraToken(jwt, entraCfg(), publicKey as CryptoKey);
  };
  aliceAuth = await mint('alice@build.test', 'oid-alice');
  carolAuth = await mint('carol@build.test', 'oid-carol');
  bobAuth = await mint('bob@build.test', 'oid-bob');
  ownerAuth = await mint('owner@build.test', 'oid-owner');

  // ── the equality oracle: capture nonexistent-slug envelopes as ALICE
  //    (masked caller) BEFORE the masked pages exist ──────────────────────
  for (const [op, mk] of READ_BY_SLUG_OPS) {
    const r = await call(op, mk(MASKED_A), aliceAuth);
    nonexistentEnvelopes.set(op, r);
  }

  // ── scratch brain (trusted local setup) ────────────────────────────────
  const put = async (slug: string, title: string, body: string) => {
    const r = await call('put_page', {
      slug,
      content: `---\ntype: note\ntitle: ${title}\n---\n${body}`,
    });
    if (r.isError) throw new Error(`setup put_page ${slug} failed: ${JSON.stringify(r.body)}`);
  };
  await put('public/handbook', 'Handbook', 'The zebrafish handbook everyone can read. '.repeat(5));
  await put('partners/alice/notes', 'Alice notes', 'Working notes for alice. '.repeat(5));
  await put(MASKED_A, 'Secret summary', 'The zebrafish restricted dossier summary. '.repeat(5));
  await put(MASKED_B, 'Case X', 'Case X zebrafish evidence file, orphaned on purpose. '.repeat(5));

  await call('add_link', { from: 'public/handbook', to: MASKED_A, link_type: 'related' });
  await call('add_link', { from: MASKED_A, to: 'public/handbook', link_type: 'related' });
  await call('add_tag', { slug: MASKED_A, tag: 'secret-tag' });
  await call('add_timeline_entry', { slug: MASKED_A, date: '2026-08-01', summary: 'secret meeting happened' });
  await call('put_raw_data', { slug: MASKED_A, source: 'test-src', data: { secret: true } });
  await call('log_ingest', {
    source_type: 'test', source_ref: 'ref-1',
    pages_updated: [MASKED_A, 'public/handbook'], summary: 'ingested both',
  });
});

afterAll(async () => { await engine.disconnect(); });

// ─────────────────────────────────────────────────────────────────────────────
// Read-side: non-invited identity — masked ≡ nonexistent
// ─────────────────────────────────────────────────────────────────────────────

describe('read masking — non-invited Entra identity (alice)', () => {
  test('direct fetch of a masked slug is BYTE-IDENTICAL to a nonexistent slug (every slug-read op)', async () => {
    for (const [op, mk] of READ_BY_SLUG_OPS) {
      const r = await call(op, mk(MASKED_A), aliceAuth);
      expect({ op, r }).toEqual({ op, r: nonexistentEnvelopes.get(op) as typeof r });
    }
  });

  test('the same ops succeed for the caller on a VISIBLE page (mask is not a blanket deny)', async () => {
    const page = await call('get_page', { slug: 'public/handbook' }, aliceAuth);
    expect(page.isError).toBe(false);
    expect(page.body.slug).toBe('public/handbook');
  });

  test('list_pages omits masked pages', async () => {
    const r = await call('list_pages', { limit: 100 }, aliceAuth);
    expect(r.isError).toBe(false);
    const slugs = (r.body as unknown as Array<{ slug: string }>).map(p => p.slug);
    expect(slugs).toContain('public/handbook');
    expect(slugs.some(s => s.startsWith('restricted/'))).toBe(false);
  });

  test('resolve_slugs never suggests a masked slug', async () => {
    const r = await call('resolve_slugs', { partial: 'restricted' }, aliceAuth);
    expect(r.isError).toBe(false);
    const arr = (r.body as unknown as { matches?: string[] }).matches
      ?? (r.body as unknown as string[]);
    expect(JSON.stringify(arr).includes('restricted/')).toBe(false);
  });

  test('search (keyword retrieval) omits masked pages but finds visible ones', async () => {
    const r = await call('search', { query: 'zebrafish' }, aliceAuth);
    expect(r.isError).toBe(false);
    const text = JSON.stringify(r.body);
    expect(text).toContain('public/handbook');
    expect(text.includes('restricted/')).toBe(false);
  });

  test('query op omits masked pages', async () => {
    const r = await call('query', { query: 'zebrafish dossier' }, aliceAuth);
    expect(r.isError).toBe(false);
    expect(JSON.stringify(r.body).includes('restricted/')).toBe(false);
  });

  test('recall verb omits masked pages', async () => {
    const r = await call('recall', { query: 'zebrafish dossier' }, aliceAuth);
    expect(r.isError).toBe(false);
    expect(JSON.stringify(r.body).includes('restricted/')).toBe(false);
  });

  test('get_backlinks on a visible page hides links ORIGINATING from masked pages', async () => {
    const r = await call('get_backlinks', { slug: 'public/handbook' }, aliceAuth);
    expect(r.isError).toBe(false);
    expect(JSON.stringify(r.body).includes('restricted/')).toBe(false);
  });

  test('traverse_graph from a visible page never reaches a masked node or edge', async () => {
    const r = await call('traverse_graph', { slug: 'public/handbook', depth: 3, direction: 'both' }, aliceAuth);
    expect(r.isError).toBe(false);
    expect(JSON.stringify(r.body).includes('restricted/')).toBe(false);
  });

  test('chronicle_day omits timeline rows from masked pages', async () => {
    const r = await call('chronicle_day', { date: '2026-08-01' }, aliceAuth);
    expect(r.isError).toBe(false);
    const text = JSON.stringify(r.body);
    expect(text.includes('restricted/')).toBe(false);
    expect(text.includes('secret meeting')).toBe(false);
  });

  test('get_recent_salience omits masked pages', async () => {
    const r = await call('get_recent_salience', { days: 30, limit: 50 }, aliceAuth);
    expect(r.isError).toBe(false);
    expect(JSON.stringify(r.body).includes('restricted/')).toBe(false);
  });

  test('find_orphans omits masked pages', async () => {
    const r = await call('find_orphans', {}, aliceAuth);
    expect(r.isError).toBe(false);
    expect(JSON.stringify(r.body).includes('restricted/')).toBe(false);
  });

  test('get_ingest_log scrubs masked slugs from pages_updated', async () => {
    const r = await call('get_ingest_log', { limit: 20 }, aliceAuth);
    expect(r.isError).toBe(false);
    const text = JSON.stringify(r.body);
    expect(text.includes('restricted/')).toBe(false);
    expect(text).toContain('public/handbook');
  });

  test('takes_list / takes_search hold (no masked page_slug rows)', async () => {
    const l = await call('takes_list', {}, aliceAuth);
    expect(l.isError).toBe(false);
    expect(JSON.stringify(l.body).includes('restricted/')).toBe(false);
    const s = await call('takes_search', { query: 'zebrafish' }, aliceAuth);
    expect(s.isError).toBe(false);
    expect(JSON.stringify(s.body).includes('restricted/')).toBe(false);
  });

  test('entity verb: a masked entity resolves found:false; suggestions never name it', async () => {
    const r = await call('entity', { name: MASKED_A }, aliceAuth);
    expect(r.isError).toBe(false);
    expect(r.body.found).toBe(false);
    expect(JSON.stringify(r.body).includes('restricted/')).toBe(false);
  });

  test('get_stats / get_health are admin-scoped, so masked identities cannot reach them at all', async () => {
    // Scope enforcement (HTTP layer) blocks read/write tokens from admin
    // ops; at the shared dispatch layer the masked-identity allow-list gate
    // denies them too — fail-closed on both paths.
    const stats = await call('get_stats', {}, aliceAuth);
    expect(stats.isError).toBe(true);
    expect(stats.body.error).toBe('permission_denied');
    // Admin identities are exempt from masking and see true totals.
    const ownerStats = await call('get_stats', {}, ownerAuth);
    expect(ownerStats.isError).toBe(false);
  });

  test('defense-in-depth: the masked engine view subtracts hidden pages/chunks from getStats', async () => {
    const raw = await engine.getStats();
    const masked = await maskEngineForRead(engine as BrainEngine, ['restricted/']).getStats();
    expect(raw.page_count - masked.page_count).toBe(2); // the two restricted/ pages
    expect(masked.chunk_count).toBeLessThanOrEqual(raw.chunk_count);
    expect(JSON.stringify(masked.pages_by_type).includes('restricted')).toBe(false);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Read-side: exempt callers see everything
// ─────────────────────────────────────────────────────────────────────────────

describe('read masking — exemptions', () => {
  test('invited Entra identity (bob) has full access to the masked tree', async () => {
    const page = await call('get_page', { slug: MASKED_A }, bobAuth);
    expect(page.isError).toBe(false);
    expect(page.body.slug).toBe(MASKED_A);
    const list = await call('list_pages', { limit: 100 }, bobAuth);
    const slugs = (list.body as unknown as Array<{ slug: string }>).map(p => p.slug);
    expect(slugs).toContain(MASKED_A);
    expect(slugs).toContain(MASKED_B);
    const search = await call('search', { query: 'zebrafish' }, bobAuth);
    expect(JSON.stringify(search.body)).toContain('restricted/');
  });

  test('admin Entra identity (owner) is exempt from masking', async () => {
    const page = await call('get_page', { slug: MASKED_A }, ownerAuth);
    expect(page.isError).toBe(false);
    const tags = await call('get_tags', { slug: MASKED_A }, ownerAuth);
    expect(JSON.stringify(tags.body)).toContain('secret-tag');
  });

  test('legacy/native token clients are exempt (owner-issued machine credentials)', async () => {
    const page = await call('get_page', { slug: MASKED_A }, legacyAuth);
    expect(page.isError).toBe(false);
    const list = await call('list_pages', { limit: 100 }, legacyAuth);
    expect(JSON.stringify(list.body)).toContain(MASKED_B);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// whoami — the entra branch (fold-in fix)
// ─────────────────────────────────────────────────────────────────────────────

describe('whoami — entra transport', () => {
  test('reports transport entra, identity, scopes, expiry, write_prefixes, masked boolean', async () => {
    const r = await call('whoami', {}, aliceAuth);
    expect(r.isError).toBe(false);
    expect(r.body.transport).toBe('entra');
    expect(r.body.upn).toBe('alice@build.test');
    expect(r.body.oid).toBe('oid-alice');
    expect((r.body.scopes as string[]).sort()).toEqual(['read', 'write']);
    expect(typeof r.body.expires_at).toBe('number');
    expect(r.body.write_prefixes).toEqual(['partners/alice/']);
    expect(r.body.masked_areas_hidden).toBe(true);
    // Never the prefix names:
    expect(JSON.stringify(r.body).includes('restricted/')).toBe(false);
  });

  test('invited + admin identities report masked_areas_hidden: false', async () => {
    const bob = await call('whoami', {}, bobAuth);
    expect(bob.body.masked_areas_hidden).toBe(false);
    const owner = await call('whoami', {}, ownerAuth);
    expect(owner.body.masked_areas_hidden).toBe(false);
    expect(owner.body.transport).toBe('entra');
  });

  test('legacy tokens still report transport legacy', async () => {
    const r = await call('whoami', {}, legacyAuth);
    expect(r.body.transport).toBe('legacy');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Write fencing
// ─────────────────────────────────────────────────────────────────────────────

describe('write fencing', () => {
  test('fenced identity: in-prefix write accepted', async () => {
    const r = await call('put_page', {
      slug: 'partners/alice/journal',
      content: '---\ntype: note\ntitle: Journal\n---\nWritten by alice.',
    }, aliceAuth);
    expect(r.isError).toBe(false);
  });

  test('fenced identity: out-of-prefix writes rejected with a scope error (put_page, delete_page, add_tag)', async () => {
    const put = await call('put_page', {
      slug: 'public/hijack',
      content: '---\ntype: note\ntitle: X\n---\nnope',
    }, aliceAuth);
    expect(put.isError).toBe(true);
    expect(put.body.error).toBe('permission_denied');

    const del = await call('delete_page', { slug: 'public/handbook' }, aliceAuth);
    expect(del.isError).toBe(true);
    expect(del.body.error).toBe('permission_denied');

    const tag = await call('add_tag', { slug: 'public/handbook', tag: 'x' }, aliceAuth);
    expect(tag.isError).toBe(true);
    expect(tag.body.error).toBe('permission_denied');
  });

  test('fenced identity: write into a masked prefix is rejected without admitting the mask', async () => {
    const r = await call('put_page', {
      slug: 'restricted/alice-sneak',
      content: '---\ntype: note\ntitle: X\n---\nnope',
    }, aliceAuth);
    expect(r.isError).toBe(true);
    expect(r.body.error).toBe('permission_denied');
    expect(String(r.body.message).toLowerCase().includes('mask')).toBe(false);
  });

  test('unfenced masked identity (carol): general writes OK, masked-prefix writes rejected', async () => {
    const ok = await call('put_page', {
      slug: 'public/carol-note',
      content: '---\ntype: note\ntitle: Carol\n---\nfine',
    }, carolAuth);
    expect(ok.isError).toBe(false);

    const denied = await call('put_page', {
      slug: 'restricted/carol-sneak',
      content: '---\ntype: note\ntitle: X\n---\nnope',
    }, carolAuth);
    expect(denied.isError).toBe(true);
    expect(denied.body.error).toBe('permission_denied');
    expect(String(denied.body.message).toLowerCase().includes('mask')).toBe(false);
  });

  test('invited fenced identity (bob): masked-prefix write accepted (invite + write_prefixes cover it)', async () => {
    const r = await call('put_page', {
      slug: 'restricted/case-x/bob-note',
      content: '---\ntype: note\ntitle: Bob\n---\nbob can see and write here.',
    }, bobAuth);
    expect(r.isError).toBe(false);
  });

  test('invited fenced identity (bob): out-of-prefix write still rejected', async () => {
    const r = await call('put_page', {
      slug: 'public/bob-out-of-bounds',
      content: '---\ntype: note\ntitle: X\n---\nnope',
    }, bobAuth);
    expect(r.isError).toBe(true);
    expect(r.body.error).toBe('permission_denied');
  });

  test('unfenceable write ops are denied to fenced AND masked identities (fail-closed allow-list)', async () => {
    for (const auth of [aliceAuth, carolAuth]) {
      const r = await call('log_ingest', {
        source_type: 'test', source_ref: 'r', pages_updated: ['x/y'], summary: 's',
      }, auth);
      expect(r.isError).toBe(true);
      expect(r.body.error).toBe('permission_denied');
    }
  });

  test('admin identity remains unfenced everywhere', async () => {
    const r = await call('put_page', {
      slug: 'restricted/owner-note',
      content: '---\ntype: note\ntitle: Owner\n---\nowner writes anywhere.',
    }, ownerAuth);
    expect(r.isError).toBe(false);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Unit: the masked engine view (surfaces not seedable above get synthetic rows)
// ─────────────────────────────────────────────────────────────────────────────

describe('maskEngineForRead (unit, stub engine)', () => {
  const HIDDEN = ['restricted/'];

  test('isSlugHidden is boundary-aware (sibling namespaces stay visible)', () => {
    expect(isSlugHidden(HIDDEN, 'restricted/x')).toBe(true);
    expect(isSlugHidden(HIDDEN, 'restricted/deep/y')).toBe(true);
    expect(isSlugHidden(HIDDEN, 'restricted-2/x')).toBe(false);
    expect(isSlugHidden(HIDDEN, 'public/restricted')).toBe(false);
    expect(isSlugHidden(HIDDEN, null)).toBe(false);
  });

  function stub(methods: Record<string, unknown>): BrainEngine {
    return methods as unknown as BrainEngine;
  }

  test('takes / facts / chronicle / fanout / aliases rows referencing hidden slugs are dropped', async () => {
    const masked = maskEngineForRead(stub({
      listTakes: async () => [
        { page_slug: 'restricted/x', claim: 'hidden' },
        { page_slug: 'public/y', claim: 'visible' },
      ],
      searchTakes: async () => [{ page_slug: 'restricted/x' }, { page_slug: 'public/y' }],
      listFactsSince: async () => [
        { entity_slug: 'restricted/person', fact: 'hidden' },
        { entity_slug: 'people/ok', fact: 'visible' },
        { entity_slug: null, fact: 'no-entity kept' },
      ],
      getOnThisDay: async () => [
        { page_slug: 'restricted/x', event_slug: null },
        { page_slug: 'public/y', event_slug: 'restricted/event' },
        { page_slug: 'public/y', event_slug: null },
      ],
      relationalFanout: async (seeds: string[]) => seeds.length === 0 ? [] : [
        { slug: 'restricted/x', path: ['a'] },
        { slug: 'public/y', path: ['a', 'restricted/mid', 'public/y'] },
        { slug: 'public/z', path: ['a', 'public/z'] },
      ],
      resolveAliases: async () => new Map([
        ['hidden-alias', [{ slug: 'restricted/x', source_id: 'default' }]],
        ['mixed-alias', [{ slug: 'restricted/x', source_id: 'default' }, { slug: 'public/y', source_id: 'default' }]],
      ]),
      getLastSeen: async () => ({ entity_slug: 'people/ok', last_date: '2026-08-01', last_event_slug: 'restricted/event', days_ago: 15 }),
      getBacklinkCounts: async (slugs: string[]) => new Map(slugs.map(s => [s, 3])),
      findTrajectory: async () => [{ fact_id: 1 }],
    }), HIDDEN);

    expect(await masked.listTakes()).toEqual([{ page_slug: 'public/y', claim: 'visible' }] as never);
    expect(await masked.searchTakes('q')).toEqual([{ page_slug: 'public/y' }] as never);
    expect((await masked.listFactsSince('default', new Date())).map(f => f.fact))
      .toEqual(['visible', 'no-entity kept']);
    expect((await masked.getOnThisDay()).length).toBe(1);
    expect((await masked.relationalFanout(['restricted/seed']))).toEqual([]);
    expect((await masked.relationalFanout(['public/seed'])).map(r => r.slug)).toEqual(['public/z']);
    const aliases = await masked.resolveAliases(['hidden-alias', 'mixed-alias']);
    expect(aliases.has('hidden-alias')).toBe(false);
    expect(aliases.get('mixed-alias')!.map(a => a.slug)).toEqual(['public/y']);
    const seen = await masked.getLastSeen('people/ok');
    expect(seen.last_event_slug).toBeNull();
    expect(seen.last_date).toBe('2026-08-01');
    const hiddenSeen = await masked.getLastSeen('restricted/person');
    expect(hiddenSeen).toEqual({ entity_slug: 'restricted/person', last_date: null, last_event_slug: null, days_ago: null });
    const counts = await masked.getBacklinkCounts(['public/y', 'restricted/x']);
    expect(counts.get('public/y')).toBe(3);
    expect(counts.get('restricted/x')).toBe(0); // identical to a nonexistent slug
    expect((await masked.findTrajectory({ entitySlug: 'restricted/person' } as never))).toEqual([]);
  });

  test('non-intercepted methods pass through bound to the raw engine', async () => {
    let called = 0;
    const masked = maskEngineForRead(stub({
      setConfig: async () => { called += 1; },
    }), HIDDEN);
    await masked.setConfig('k', 'v');
    expect(called).toBe(1);
  });
});
