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
        "federated_read": ["wiki", "default"]              // read set
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
