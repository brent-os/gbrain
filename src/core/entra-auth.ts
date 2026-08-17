/**
 * Microsoft Entra ID (Azure AD) JWT validation + DCR-shim helpers.
 *
 * Lets humans sign in to a gbrain server with their existing M365 accounts:
 * the server verifies Entra-issued JWTs against the tenant's JWKS and maps the
 * verified identity (oid / preferred_username) to gbrain scopes. Because MCP
 * clients require Dynamic Client Registration (RFC 7591) and Entra has none,
 * the server also advertises ITSELF as the authorization server and proxies
 * authorize/token to Entra with a sanitized parameter set (see below).
 *
 * Feature-gated: when disabled (`resolveEntraConfig` returns null) nothing in
 * this module runs and the native OAuth surface is untouched. When enabled,
 * BOTH auth paths live simultaneously — JWT bearer tokens verify against
 * Entra, everything else falls through to the existing verification — so
 * existing token clients keep working during migration.
 *
 * Three empirical findings from the 2026-08-16 spike, carried as invariants:
 *
 *  1. claude.ai's backend cannot reach non-443 ports. Deploy concern only
 *     (put the server behind a reverse proxy on 443) — no code impact.
 *  2. claude.ai appends `resource=<url>` (RFC 8707) and `prompt=consent` to
 *     BOTH the authorize request and the token request. Entra's v2 endpoints
 *     reject `resource` (authorize: bounced with an error page; token: 400
 *     AADSTS9010010 invalid_target). The proxy therefore SANITIZES:
 *     /oauth/authorize forwards ONLY the `AUTHORIZE_FORWARD_PARAMS` whitelist
 *     (plus server-injected client_id + scope); /oauth/token forwards the
 *     client's form MINUS `resource`, with client_id + client_secret injected
 *     server-side, and injects the full scope string on refresh_token grants
 *     when scope is absent (Entra otherwise refreshes down to Graph scopes
 *     and the returned access token stops being for our API).
 *  3. Entra apps registered via the portal default to issuing v1-format
 *     access tokens for custom APIs (issuer https://sts.windows.net/<tenant>/)
 *     unless the app manifest sets `requestedAccessTokenVersion: 2`. This
 *     module validates against the v2 issuer by default; `accept_v1_issuer`
 *     is an opt-in transition aid, NOT the recommended posture. Production
 *     apps must set requestedAccessTokenVersion: 2.
 *
 * Config plane: env vars (GBRAIN_ENTRA_*) win over the `entra` block in
 * ~/.gbrain/config.json — the same env-over-file precedence loadConfig()
 * uses for every other key. See docs/entra-auth.md for the full reference.
 */

import { createRemoteJWKSet, jwtVerify, decodeProtectedHeader } from 'jose';
import type { JWTPayload, JWTVerifyGetKey } from 'jose';
import { InvalidTokenError } from '@modelcontextprotocol/sdk/server/auth/errors.js';
import type { AuthInfo as SdkAuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import type { AuthInfo as CoreAuthInfo } from './operations.ts';
import { parseScopeString, assertAllowedScopes } from './scope.ts';

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/** What a mapped identity is allowed to do on this brain. */
export interface EntraIdentityGrant {
  /** gbrain scopes (validated against ALLOWED_SCOPES, e.g. ['read','write']). */
  scopes: string[];
  /** Optional write-source binding — same axis as oauth_clients.source_id. */
  sourceId?: string;
  /** Optional federated read set — same axis as oauth_clients.federated_read. */
  federatedRead?: string[];
}

export interface EntraConfig {
  tenantId: string;
  clientId: string;
  /** Required: the token proxy injects it server-side on every exchange. */
  clientSecret: string;
  /** The custom-API scope, default `api://<clientId>/access`. */
  apiScope: string;
  /**
   * Transition aid (finding 3): ALSO accept the v1 issuer
   * `https://sts.windows.net/<tenant>/`. Default false — fix the app
   * manifest (`requestedAccessTokenVersion: 2`) instead of enabling this.
   */
  acceptV1Issuer: boolean;
  /**
   * Verified identity → grant. Keys are lowercased and matched
   * case-insensitively against `preferred_username` (UPN) or `oid`.
   */
  identityMap: Map<string, EntraIdentityGrant>;
  /**
   * Grant for identities in the tenant that are NOT in identityMap.
   * Default [] = DENY: a valid Entra token from an unmapped user is
   * rejected. Fail-closed — set default_scopes explicitly to open up.
   */
  defaultScopes: string[];
}

/** File-plane shape (`entra` block in ~/.gbrain/config.json). */
export interface EntraFileConfig {
  enabled?: boolean;
  tenant_id?: string;
  client_id?: string;
  client_secret?: string;
  api_scope?: string;
  accept_v1_issuer?: boolean;
  identity_map?: Record<string, EntraIdentityMapEntry>;
  default_scopes?: string[] | string;
}

/**
 * Accepted per-identity shapes in identity_map:
 *   "read write"                        — scope string
 *   ["read", "write"]                   — scope array
 *   { scopes, source_id, federated_read } — full grant object
 */
export type EntraIdentityMapEntry =
  | string
  | string[]
  | { scopes: string | string[]; source_id?: string; federated_read?: string[] };

function parseBoolEnv(v: string | undefined): boolean | undefined {
  if (v === undefined || v === '') return undefined;
  if (v === '1' || v.toLowerCase() === 'true') return true;
  if (v === '0' || v.toLowerCase() === 'false') return false;
  return undefined;
}

function normalizeScopes(raw: string | string[] | undefined, label: string): string[] {
  const scopes = Array.isArray(raw)
    ? raw.flatMap(s => parseScopeString(s))
    : parseScopeString(typeof raw === 'string' ? raw.replace(/,/g, ' ') : undefined);
  try {
    assertAllowedScopes(scopes);
  } catch (e) {
    throw new Error(`Entra config: ${label}: ${e instanceof Error ? e.message : String(e)}`);
  }
  return scopes;
}

function normalizeGrant(entry: EntraIdentityMapEntry, key: string): EntraIdentityGrant {
  if (typeof entry === 'string' || Array.isArray(entry)) {
    return { scopes: normalizeScopes(entry, `identity_map["${key}"]`) };
  }
  return {
    scopes: normalizeScopes(entry.scopes, `identity_map["${key}"]`),
    ...(entry.source_id ? { sourceId: entry.source_id } : {}),
    ...(entry.federated_read ? { federatedRead: entry.federated_read } : {}),
  };
}

/**
 * Resolve the effective Entra config. Returns null when the feature is
 * disabled (the default); throws a descriptive Error when it is enabled but
 * incomplete — an operator who turned Entra on wants a loud startup failure,
 * not a silent fall-through to native-only auth.
 *
 * Precedence: GBRAIN_ENTRA_* env vars over the file-plane `entra` block.
 * GBRAIN_ENTRA_ENABLED=0 force-disables even when the file says enabled
 * (the documented rollback lever).
 */
export function resolveEntraConfig(
  fileEntra?: EntraFileConfig | null,
  env: NodeJS.ProcessEnv = process.env,
): EntraConfig | null {
  const envEnabled = parseBoolEnv(env.GBRAIN_ENTRA_ENABLED);
  const enabled = envEnabled !== undefined ? envEnabled : fileEntra?.enabled === true;
  if (!enabled) return null;

  const tenantId = env.GBRAIN_ENTRA_TENANT_ID || fileEntra?.tenant_id;
  const clientId = env.GBRAIN_ENTRA_CLIENT_ID || fileEntra?.client_id;
  const clientSecret = env.GBRAIN_ENTRA_CLIENT_SECRET || fileEntra?.client_secret;
  const missing = [
    !tenantId ? 'tenant id (GBRAIN_ENTRA_TENANT_ID / entra.tenant_id)' : null,
    !clientId ? 'client id (GBRAIN_ENTRA_CLIENT_ID / entra.client_id)' : null,
    !clientSecret ? 'client secret (GBRAIN_ENTRA_CLIENT_SECRET / entra.client_secret)' : null,
  ].filter((m): m is string => m !== null);
  if (missing.length > 0 || !tenantId || !clientId || !clientSecret) {
    throw new Error(`Entra auth is enabled but incomplete — missing: ${missing.join(', ')}`);
  }

  const apiScope = env.GBRAIN_ENTRA_API_SCOPE || fileEntra?.api_scope || `api://${clientId}/access`;
  const envV1 = parseBoolEnv(env.GBRAIN_ENTRA_ACCEPT_V1_ISSUER);
  const acceptV1Issuer = envV1 !== undefined ? envV1 : fileEntra?.accept_v1_issuer === true;

  let rawMap: Record<string, EntraIdentityMapEntry> = fileEntra?.identity_map ?? {};
  if (env.GBRAIN_ENTRA_IDENTITY_MAP) {
    try {
      rawMap = JSON.parse(env.GBRAIN_ENTRA_IDENTITY_MAP) as Record<string, EntraIdentityMapEntry>;
    } catch (e) {
      throw new Error(
        `Entra config: GBRAIN_ENTRA_IDENTITY_MAP is not valid JSON: ${e instanceof Error ? e.message : String(e)}`,
      );
    }
  }
  const identityMap = new Map<string, EntraIdentityGrant>();
  for (const [key, entry] of Object.entries(rawMap)) {
    identityMap.set(key.toLowerCase(), normalizeGrant(entry, key));
  }

  const defaultScopes = normalizeScopes(
    env.GBRAIN_ENTRA_DEFAULT_SCOPES ?? fileEntra?.default_scopes,
    'default_scopes',
  );

  return { tenantId, clientId, clientSecret, apiScope, acceptV1Issuer, identityMap, defaultScopes };
}

// ---------------------------------------------------------------------------
// Entra endpoints
// ---------------------------------------------------------------------------

export function entraV2Issuer(cfg: EntraConfig): string {
  return `https://login.microsoftonline.com/${cfg.tenantId}/v2.0`;
}

export function entraV1Issuer(cfg: EntraConfig): string {
  return `https://sts.windows.net/${cfg.tenantId}/`;
}

export function entraAuthorizeEndpoint(cfg: EntraConfig): string {
  return `https://login.microsoftonline.com/${cfg.tenantId}/oauth2/v2.0/authorize`;
}

export function entraTokenEndpoint(cfg: EntraConfig): string {
  return `https://login.microsoftonline.com/${cfg.tenantId}/oauth2/v2.0/token`;
}

export function entraJwksUrl(cfg: EntraConfig): string {
  return `https://login.microsoftonline.com/${cfg.tenantId}/discovery/v2.0/keys`;
}

/**
 * The scope string the shim requests from Entra. The API scope forces the
 * issued access token's `aud` to our app; openid/profile/email carry the
 * identity claims; offline_access mints a refresh token.
 */
export function entraScopes(cfg: EntraConfig): string[] {
  return [cfg.apiScope, 'openid', 'profile', 'email', 'offline_access'];
}

// ---------------------------------------------------------------------------
// DCR-shim param sanitization (finding 2)
// ---------------------------------------------------------------------------

/**
 * The ONLY client-supplied params forwarded to Entra's /authorize. Everything
 * else — `resource` (RFC 8707, rejected by Entra v2), `prompt=consent`, the
 * client's own client_id/scope — is dropped; the server injects its
 * registered client_id and the full scope string instead.
 */
export const AUTHORIZE_FORWARD_PARAMS = [
  'response_type',
  'redirect_uri',
  'state',
  'code_challenge',
  'code_challenge_method',
] as const;

export function sanitizeAuthorizeParams(incoming: URLSearchParams, cfg: EntraConfig): URLSearchParams {
  const q = new URLSearchParams();
  for (const k of AUTHORIZE_FORWARD_PARAMS) {
    const v = incoming.get(k);
    if (v) q.set(k, v);
  }
  q.set('client_id', cfg.clientId);
  q.set('scope', entraScopes(cfg).join(' '));
  return q;
}

/**
 * Sanitize the client's token-exchange form before proxying to Entra:
 *  - drop `resource` (RFC 8707 — Entra v2 rejects it with AADSTS9010010)
 *  - inject client_id + client_secret server-side (never sent to the client)
 *  - on refresh_token grants without a scope, inject the full scope string
 *    so the refreshed access token is still for our API
 */
export function sanitizeTokenForm(incoming: URLSearchParams, cfg: EntraConfig): URLSearchParams {
  const form = new URLSearchParams(incoming);
  form.delete('resource');
  form.set('client_id', cfg.clientId);
  form.set('client_secret', cfg.clientSecret);
  if (form.get('grant_type') === 'refresh_token' && !form.get('scope')) {
    form.set('scope', entraScopes(cfg).join(' '));
  }
  return form;
}

// ---------------------------------------------------------------------------
// DCR-shim metadata + fake registration
// ---------------------------------------------------------------------------

/**
 * RFC 8414 authorization-server metadata pointing every endpoint at the
 * gbrain server itself (the shim), never directly at Entra — MCP clients
 * need /register, which Entra lacks.
 */
export function buildAuthServerMetadata(serverOrigin: string, cfg: EntraConfig): Record<string, unknown> {
  const origin = serverOrigin.replace(/\/$/, '');
  return {
    issuer: origin,
    authorization_endpoint: `${origin}/oauth/authorize`,
    token_endpoint: `${origin}/oauth/token`,
    registration_endpoint: `${origin}/oauth/register`,
    scopes_supported: entraScopes(cfg),
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['none'],
  };
}

/** RFC 9728 protected-resource metadata naming the server as its own AS. */
export function buildProtectedResourceMetadata(serverOrigin: string, cfg: EntraConfig): Record<string, unknown> {
  const origin = serverOrigin.replace(/\/$/, '');
  return {
    resource: `${origin}/mcp`,
    authorization_servers: [origin],
    scopes_supported: entraScopes(cfg),
    bearer_methods_supported: ['header'],
  };
}

/**
 * Fake DCR response (201): every registering client is handed the ONE
 * configured Entra client_id. PKCE-only (`token_endpoint_auth_method: none`)
 * — the real secret stays server-side in the token proxy.
 */
export function buildRegisterResponse(
  cfg: EntraConfig,
  body: Record<string, unknown> | null | undefined,
): Record<string, unknown> {
  const b = body ?? {};
  return {
    client_id: cfg.clientId,
    client_id_issued_at: Math.floor(Date.now() / 1000),
    token_endpoint_auth_method: 'none',
    client_name: typeof b.client_name === 'string' ? b.client_name : 'claude',
    grant_types: Array.isArray(b.grant_types) && b.grant_types.length > 0
      ? b.grant_types
      : ['authorization_code', 'refresh_token'],
    response_types: Array.isArray(b.response_types) && b.response_types.length > 0
      ? b.response_types
      : ['code'],
    redirect_uris: Array.isArray(b.redirect_uris) ? b.redirect_uris : [],
  };
}

// ---------------------------------------------------------------------------
// JWT verification + identity → permission mapping
// ---------------------------------------------------------------------------

/**
 * Cheap structural test: is this presented bearer token a JWT (three
 * base64url segments whose header decodes)? Native gbrain tokens
 * (`gbrain_at_…`, legacy `gbrain_…` hex) contain no dots and fall through
 * to the existing verification path unchanged.
 */
export function looksLikeJwt(token: string): boolean {
  if (!/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token)) return false;
  try {
    decodeProtectedHeader(token);
    return true;
  } catch {
    return false;
  }
}

/**
 * Map a verified token payload to a grant. Match order: preferred_username
 * (UPN, case-insensitive) → oid → default_scopes. Returns null when the
 * identity is unmapped AND default_scopes is empty (deny).
 */
export function resolveIdentityGrant(cfg: EntraConfig, payload: JWTPayload): EntraIdentityGrant | null {
  const upn = typeof payload.preferred_username === 'string'
    ? payload.preferred_username.toLowerCase()
    : undefined;
  const oid = typeof payload.oid === 'string' ? payload.oid.toLowerCase() : undefined;
  const grant = (upn && cfg.identityMap.get(upn)) || (oid && cfg.identityMap.get(oid)) || null;
  if (grant) return grant;
  if (cfg.defaultScopes.length > 0) return { scopes: cfg.defaultScopes };
  return null;
}

/** The key material jwtVerify accepts; injectable so tests skip the JWKS fetch. */
export type EntraVerifyKey = JWTVerifyGetKey | CryptoKey | Uint8Array;

/**
 * Verify an Entra-issued JWT and produce the same AuthInfo shape the rest of
 * gbrain consumes (verifyAccessToken parity):
 *  - signature via the tenant's JWKS (or the injected test key)
 *  - issuer: v2 by default; + v1 only when accept_v1_issuer (finding 3)
 *  - audience: the app's client id or `api://<client id>`
 *  - identity → scopes via resolveIdentityGrant (fail-closed for unmapped)
 *
 * Identity threading for authorship: `clientId` is the stable
 * `entra:<oid>`, `clientName` is the human-readable UPN — the /mcp audit
 * path stamps both into mcp_request_log (token_name / agent_name), so every
 * write is attributable to the verified person. The raw claims ride on
 * `AuthInfo.entra` for future consumers.
 *
 * Throws the SDK's InvalidTokenError on any failure so requireBearerAuth
 * renders the same 401 + WWW-Authenticate shape as native token failures.
 */
export async function verifyEntraToken(
  token: string,
  cfg: EntraConfig,
  key: EntraVerifyKey,
): Promise<CoreAuthInfo> {
  const issuers = cfg.acceptV1Issuer
    ? [entraV2Issuer(cfg), entraV1Issuer(cfg)]
    : [entraV2Issuer(cfg)];
  let payload: JWTPayload;
  try {
    // The cast collapses jose's per-key-type overloads; every member of
    // EntraVerifyKey is individually a valid jwtVerify key argument.
    const result = await jwtVerify(token, key as JWTVerifyGetKey, {
      issuer: issuers,
      audience: [cfg.clientId, `api://${cfg.clientId}`],
    });
    payload = result.payload;
  } catch (e) {
    throw new InvalidTokenError(
      `Entra token rejected: ${e instanceof Error ? e.message : String(e)}`,
    );
  }

  const grant = resolveIdentityGrant(cfg, payload);
  if (!grant) {
    throw new InvalidTokenError(
      'Entra identity is not authorized for this brain (not in identity_map and default_scopes is empty)',
    );
  }

  const oid = typeof payload.oid === 'string' ? payload.oid : undefined;
  const upn = typeof payload.preferred_username === 'string' ? payload.preferred_username : undefined;
  const name = typeof payload.name === 'string' ? payload.name : undefined;
  const tid = typeof payload.tid === 'string' ? payload.tid : undefined;

  return {
    token,
    clientId: `entra:${oid ?? upn ?? 'unknown'}`,
    clientName: upn ?? name ?? oid,
    scopes: grant.scopes,
    expiresAt: typeof payload.exp === 'number' ? payload.exp : 0,
    ...(grant.sourceId ? { sourceId: grant.sourceId } : {}),
    ...(grant.federatedRead ? { allowedSources: grant.federatedRead } : {}),
    entra: {
      oid: oid ?? '',
      ...(upn ? { preferredUsername: upn } : {}),
      ...(name ? { name } : {}),
      ...(tid ? { tid } : {}),
    },
  };
}

/**
 * Stateful wrapper caching the remote JWKS resolver (jose fetches + caches
 * keys on first use, refreshing on unknown-kid). Tests inject a local
 * public key via `opts.key` — no network, no JWKS mock needed.
 */
export class EntraTokenVerifier {
  private readonly key: EntraVerifyKey;

  constructor(private readonly cfg: EntraConfig, opts: { key?: EntraVerifyKey } = {}) {
    this.key = opts.key ?? createRemoteJWKSet(new URL(entraJwksUrl(cfg)));
  }

  async verifyAccessToken(token: string): Promise<CoreAuthInfo> {
    return verifyEntraToken(token, this.cfg, this.key);
  }
}

/**
 * Compose the Entra branch with the existing verifier for requireBearerAuth:
 * JWTs go to Entra, everything else (native `gbrain_at_…` OAuth tokens,
 * legacy access_tokens) falls through UNCHANGED. A JWT that fails Entra
 * verification does NOT fall through — it was never a native token, and
 * retrying it against the DB would only blur the 401 reason.
 */
export function createEntraAwareVerifier(
  entra: EntraTokenVerifier,
  fallback: { verifyAccessToken(token: string): Promise<SdkAuthInfo> },
): { verifyAccessToken(token: string): Promise<SdkAuthInfo> } {
  return {
    async verifyAccessToken(token: string): Promise<SdkAuthInfo> {
      if (looksLikeJwt(token)) {
        return (await entra.verifyAccessToken(token)) as CoreAuthInfo as SdkAuthInfo;
      }
      return fallback.verifyAccessToken(token);
    },
  };
}
