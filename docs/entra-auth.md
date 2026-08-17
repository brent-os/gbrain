# Entra JWT auth (Microsoft Entra ID / Azure AD)

`gbrain serve --http` can verify Microsoft Entra ID–issued JWTs so humans sign
in with their existing M365 accounts. The server validates tokens against the
tenant's JWKS, maps the verified identity (UPN or oid) to gbrain scopes, and —
because MCP clients require Dynamic Client Registration and Entra has none —
serves a small DCR-shim proxy that advertises the server as its own
authorization server and forwards authorize/token to Entra with a sanitized
parameter set.

Feature-gated and migration-safe: when disabled, nothing changes. When
enabled, **both auth paths live simultaneously** — Entra JWTs verify against
the tenant, native OAuth tokens (`gbrain_at_…`) and legacy bearer tokens keep
working unchanged — so you can move clients over one at a time.

Implementation: `src/core/entra-auth.ts` (verification, sanitization, config)
wired into `src/commands/serve-http.ts` (Express/OAuth transport, incl. the
DCR shim) and `src/mcp/http-transport.ts` (legacy bearer transport,
verification only). Tests: `test/entra-auth.test.ts`.

## Config reference

Env vars win over the `entra` block in `~/.gbrain/config.json` (the same
env-over-file precedence `loadConfig()` uses everywhere else). Enabling the
feature with an incomplete config **refuses to start** — fail loud, never a
silent fall-through to native-only auth.

| Env var | config.json (`entra.*`) | Required | Meaning |
|---|---|---|---|
| `GBRAIN_ENTRA_ENABLED` | `enabled` | yes (to turn on) | `1`/`true` on; `0`/`false` force-off (overrides file — the rollback lever) |
| `GBRAIN_ENTRA_TENANT_ID` | `tenant_id` | yes | Entra tenant (directory) id |
| `GBRAIN_ENTRA_CLIENT_ID` | `client_id` | yes | App registration's client id |
| `GBRAIN_ENTRA_CLIENT_SECRET` | `client_secret` | yes | Client secret — injected server-side by the token proxy, never sent to MCP clients |
| `GBRAIN_ENTRA_API_SCOPE` | `api_scope` | no | Custom-API scope; default `api://<client_id>/access` |
| `GBRAIN_ENTRA_ACCEPT_V1_ISSUER` | `accept_v1_issuer` | no | Default `false`. Transition aid only — see finding 3 below |
| `GBRAIN_ENTRA_IDENTITY_MAP` | `identity_map` | no | JSON: identity → grant (see below). Env value replaces the file map wholesale |
| `GBRAIN_ENTRA_DEFAULT_SCOPES` | `default_scopes` | no | Grant for tenant identities NOT in the map. Default empty = **DENY** |
| `GBRAIN_ENTRA_MASKED_PREFIXES` | `masked_prefixes` | no | JSON: slug prefix → invited identities (see Identity ACL below). Env value replaces the file map wholesale |

### Identity → permission mapping

Keys are matched case-insensitively against the token's `preferred_username`
(UPN) first, then `oid`. Values take three shapes:

```jsonc
{
  "entra": {
    "enabled": true,
    "tenant_id": "<tenant-guid>",
    "client_id": "<client-guid>",
    "client_secret": "<secret>",
    "identity_map": {
      "alice@acme-example.com": "read write",             // scope string
      "bob@acme-example.com": ["read"],                    // scope array
      "00000000-oid-guid": {                               // full grant object
        "scopes": "read write",
        "source_id": "wiki",                               // write-source binding
        "federated_read": ["wiki", "default"],             // read set
        "write_prefixes": ["partners/carol/"]              // slug write fence (see Identity ACL)
      }
    },
    "default_scopes": []                                    // unmapped ⇒ deny
  }
}
```

Scopes are validated against the standard gbrain allowlist
(`read write admin sources_admin users_admin agent`, `src/core/scope.ts`).
`source_id` / `federated_read` ride the same `AuthInfo.sourceId` /
`AuthInfo.allowedSources` axes as OAuth-client rows, so source isolation and
federated reads behave identically. Note the `/ingest` route requires the
literal `write` scope (the SDK middleware does exact-match), so grant
`read write` rather than relying on `admin` implication for webhook users.

**Authorship:** verified identity is threaded through the standard `AuthInfo`
— `clientId` = `entra:<oid>` (stable), `clientName` = UPN — so every request
row in `mcp_request_log` (`token_name` / `agent_name`) and the `whoami` op
stamp the actual person. Raw claims (`oid`, `preferred_username`, `name`,
`tid`) also ride on `AuthInfo.entra` for future consumers.

## Identity ACL — read masking + write fencing

Two per-identity controls layer on top of the scope grants. Both reuse the
`bound_slug_prefixes` machinery — the same prefix grammar (non-empty,
lowercase, trailing `/` or `/*`), the same `assertValidSlugPrefixes`
validation at startup, and the same boundary-aware matcher
(`slugUnderBoundPrefixes`) — so one prefix means one thing everywhere.

### `write_prefixes` — per-identity write fence

An identity-map grant object may carry `write_prefixes: string[]`. When set
and non-empty, every slug-mutating write by that identity must target a slug
under one of the prefixes. This rides `AuthInfo.boundSlugPrefixes`, so
enforcement is the EXISTING OAuth-client fence, unchanged:

- The allow-listed write ops (`put_page`, `delete_page`, `restore_page`,
  `add_tag`/`remove_tag`, `add_link`/`remove_link`, `add_timeline_entry`,
  `revert_version`, `put_raw_data`, `think`, `submit_agent`) reject
  out-of-prefix slugs with a `permission_denied` scope error — a fence, not
  a mask; the error is plain and names the slug.
- Every OTHER non-read op (`log_ingest`, `remember`/`forget`,
  `extract_*`, …) is denied outright at dispatch
  (`enforceBoundClientOpAllowList`) — those ops cannot be prefix-fenced, so
  fenced identities lose them entirely rather than gaining a hole. This is
  deliberately stricter than a per-slug check for the memory verbs.
- `POST /ingest` is refused for fenced (and masked) identities for the same
  reason it is refused for slug-bound OAuth clients.

Absent or `[]` = unfenced (the owner case; scopes still apply).

### `masked_prefixes` — read subsets with existence hiding

Top-level `entra.masked_prefixes` maps a slug prefix to the identities
(lowercased UPN or oid, matched case-insensitively) invited to see it:

```jsonc
{
  "entra": {
    "masked_prefixes": {
      "restricted/":        ["owner@acme-example.com", "9ed97177-0000-0000-0000-000000000000"],
      "restricted/case-x/": ["partner-c@acme-example.com"]
    }
  }
}
```

At token-verification time the server computes the set of masked prefixes
the caller is NOT invited to and threads it as
`AuthInfo.hiddenSlugPrefixes`. The shared dispatch layer
(`buildOperationContext` in `src/mcp/dispatch.ts`) then swaps the op
context's engine for a masked read view (`src/core/read-mask.ts`) in which
those pages **do not exist**:

- A direct fetch of a masked slug (`get_page`, `get_chunks`, `get_tags`,
  `get_timeline`, `get_links`/`get_backlinks`, `get_versions`,
  `get_raw_data`, `traverse_graph`, …) produces the **byte-identical
  response** a truly nonexistent slug produces — same error code, same
  message. Never a 403 that admits existence.
- List/search/graph/chronicle surfaces (`search`, `query`, `recall`,
  `list_pages`, `resolve_slugs`, `entity`, `synthesize` retrieval,
  `chronicle_*`, `get_recent_salience`, `find_*`, `takes_*`,
  `get_ingest_log`, backlinks of visible pages, alias resolution, graph
  traversal) simply omit masked pages, and edges/rows that would name one.
- Masked callers bypass the query cache in both directions (cache rows are
  not identity-keyed).
- Writes into a masked prefix require BOTH an invite and (if fenced) a
  covering write prefix — you can't write where you can't see. The
  rejection reads like an ordinary write-grant error and never says "masked".

**Exemptions (full visibility, by design):** the local CLI, native OAuth
clients, legacy bearer tokens, and **admin-scoped Entra identities**.
Native/legacy tokens are owner-issued machine credentials; partners only
ever get Entra sign-in, so the Entra path is the enforcement surface.
`whoami` reports `masked_areas_hidden: true|false` for Entra callers —
a boolean only, never the prefix names.

### Admin discipline

Only the owner should hold `admin` (admin is exempt from masking and from
the write fence gate). The startup banner prints how many mapped identities
hold admin (`N with admin`) plus the masked-prefix count, and warns loudly
if `default_scopes` grants admin to every tenant identity.

### BUILD-style deployment example

Partners read the whole brain except `restricted/`, write only their own
folder; only the owner holds admin:

```bash
GBRAIN_ENTRA_IDENTITY_MAP='{
  "owner@example.com": "read write admin",
  "partner-a@example.com": {"scopes": "read write", "write_prefixes": ["partners/partner-a/"]},
  "partner-b@example.com": {"scopes": "read write", "write_prefixes": ["partners/partner-b/"]}
}'
GBRAIN_ENTRA_MASKED_PREFIXES='{"restricted/": ["owner@example.com"]}'
```

(The owner's admin scope already exempts them from masking; listing them as
an invitee is belt-and-braces for the day the scope changes.)

### Known limits and caveats (read before relying on the mask)

- **Masking is Entra-path only.** Anyone holding a native OAuth or legacy
  bearer token sees everything. Do not hand those tokens to partners.
- **Aggregate counts other than page/chunk stats are not adjusted.**
  `get_stats`/`get_health` are admin-scoped (masked identities cannot call
  them; admins are exempt), and the masked engine view additionally
  subtracts hidden pages/chunks as defense in depth — but
  `list_link_sources` provenance counts, anomaly cohort statistics, takes
  scorecard/calibration aggregates, and backlink-count boosts inside search
  ranking are computed over the full corpus. These reveal at most that
  *some* number changed, never a slug or content.
- **Derived content is only masked where it carries a slug.** A fact row
  extracted from a masked page whose `entity_slug` points at a VISIBLE
  entity remains visible (the fact text itself may paraphrase masked
  content). Keep extraction off for masked trees, or accept this.
- **`getLastSeen` redacts a masked most-recent event's slug but keeps the
  date** — the date alone names no page.
- **Result lists may run short.** Post-filtering happens after SQL LIMIT,
  so a page of results can contain fewer rows than `limit`. This is plain
  omission, not a distinguishable marker.
- **No timing guarantees.** Masked direct fetches short-circuit before the
  DB read; a timing oracle could in principle distinguish them. Spec'd as
  acceptable (no *cheaply avoidable* timing shortcuts beyond this).
- **Write probes can reveal that a masked PREFIX exists (never its pages).**
  The masked-write fence rejects by prefix, uniformly, whether or not any
  page exists under the probed slug — so an identity holding `write` scope
  and no `write_prefixes` (unusual for partners) could notice that writes
  under `restricted/` fail while writes elsewhere succeed. Individual page
  existence and content stay hidden. Fenced partners can't run this probe:
  every out-of-prefix write fails identically.
- **Engine methods not on the mask's intercept table pass through.** All
  read surfaces reachable over remote MCP are covered (see the table in
  `src/core/read-mask.ts`); ops that read via `executeRaw`
  (`extraction_pending`, `schema_review_orphans`, the `entity` card's raw
  arms) carry their own per-tool filters. A NEW op that reads raw SQL must
  add its own filter — grep for `slugHiddenFromCaller`.

## Entra app registration requirements

1. App registration with a client secret.
2. **Expose an API**: set the Application ID URI to `api://<client-id>` and
   add a scope named `access` (delegated, admin+users consent). This is what
   `api_scope` refers to.
3. Redirect URIs (web platform) for every MCP client you'll connect, e.g.
   `https://claude.ai/api/mcp/auth_callback`.
4. **Manifest: set `requestedAccessTokenVersion: 2`** (see finding 3).

## The three spike findings (deployment notes)

Empirically established 2026-08-16 against a live tenant; these are the
reasons the code looks the way it does.

### 1. claude.ai's backend can only reach port 443

claude.ai's connector backend cannot reach non-443 ports at all — a server on
`https://host:8443` never receives the discovery probe. **Deploy behind a
reverse proxy (Caddy/nginx) terminating TLS on 443.** No code impact; purely
a deploy constraint. (Claude Code and other local clients don't share it.)

### 2. Param sanitization is mandatory (RFC 8707 `resource`)

claude.ai appends `resource=<server-url>` (RFC 8707) and `prompt=consent` to
**both** the authorize request and the token request. Entra's v2 endpoints
reject `resource`: /authorize bounces to an error page; /token returns
`400 AADSTS9010010 invalid_target`. The shim therefore:

- **/oauth/authorize** forwards ONLY `response_type`, `redirect_uri`,
  `state`, `code_challenge`, `code_challenge_method`, then injects the
  server's `client_id` and full scope string
  (`<api_scope> openid profile email offline_access`). Everything else the
  client sent is dropped.
- **/oauth/token** forwards the client's form MINUS `resource`, injects
  `client_id` + `client_secret` server-side, and injects the full scope
  string on `refresh_token` grants that arrive without one (otherwise Entra
  refreshes down to Graph scopes and the new access token stops being for
  our API). Entra's response is returned verbatim (status + body).

### 3. v2 issuer by default; `requestedAccessTokenVersion: 2` in production

Entra apps registered via the portal default to issuing **v1-format access
tokens for custom APIs** (issuer `https://sts.windows.net/<tenant>/`) unless
the app manifest sets `requestedAccessTokenVersion: 2`. gbrain validates
against the v2 issuer (`https://login.microsoftonline.com/<tenant>/v2.0`) by
default. If you're stuck on a v1-issuing app mid-migration, set
`accept_v1_issuer: true` to ALSO accept the v1 issuer — then fix the manifest
and turn the flag back off. **Production apps must set
`requestedAccessTokenVersion: 2`; the flag is a transition aid, not a
destination.**

## Deploy runbook (existing box)

1. **Entra side**: confirm the app registration matches the requirements
   above (esp. `requestedAccessTokenVersion: 2` and the client's redirect
   URI).
2. **Env additions** to the server's env file (e.g. a systemd
   `EnvironmentFile=`):

   ```bash
   GBRAIN_ENTRA_ENABLED=1
   GBRAIN_ENTRA_TENANT_ID=<tenant-guid>
   GBRAIN_ENTRA_CLIENT_ID=<client-guid>
   GBRAIN_ENTRA_CLIENT_SECRET=<secret>
   GBRAIN_ENTRA_API_SCOPE=api://<client-guid>/access
   GBRAIN_ENTRA_IDENTITY_MAP='{"you@yourtenant.com":"read write admin"}'
   # GBRAIN_ENTRA_DEFAULT_SCOPES=read        # optional; omit ⇒ unmapped = deny
   ```

3. **Serve flags**: `--public-url https://<host>` must be set (discovery
   metadata advertises this origin) and the box must answer on **443** via
   the reverse proxy (finding 1).
4. **Restart** the server. The startup log prints
   `Entra auth ENABLED (tenant …)` with the mapped-identity count.
5. **Sanity probes**:

   ```bash
   curl -s https://<host>/.well-known/oauth-authorization-server | jq .issuer
   # → "https://<host>"  (the shim, not Entra)
   curl -si https://<host>/mcp -X POST | grep -i www-authenticate
   # → Bearer … resource_metadata="https://<host>/.well-known/oauth-protected-resource"
   ```

6. **Re-point the claude.ai connector** at `https://<host>/mcp` and sign in —
   the browser lands on login.microsoftonline.com, and the whoami tool should
   report the mapped identity/scopes.
7. **Old tokens keep working** until you remove them: native OAuth clients and
   legacy bearer tokens verify exactly as before (only *discovery* is taken
   over by the shim). Migrate clients at leisure, then revoke the native
   clients (`gbrain auth …` / admin UI) when done.

## Rollback

Set `GBRAIN_ENTRA_ENABLED=0` (or remove the env block / `entra` config) and
restart. The server returns to native-only auth: SDK discovery metadata, the
native `/authorize`–`/token`–`/register` surface, and all existing tokens are
untouched — Entra-issued JWTs simply stop verifying. No data migration in
either direction; the feature holds no server-side state.
