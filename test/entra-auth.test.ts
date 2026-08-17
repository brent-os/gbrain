/**
 * Entra JWT auth unit tests (src/core/entra-auth.ts).
 *
 * Pure-unit: no DB, no network, no process.env mutation. Env resolution is
 * tested by passing explicit env objects to resolveEntraConfig; JWT
 * verification uses a locally generated RSA keypair injected in place of the
 * remote JWKS resolver, so the exact issuer/audience/signature checks run
 * against real jose verification without any fetch.
 *
 * Pins the three spike findings (2026-08-16):
 *  - authorize-param sanitization (claude.ai appends `resource` +
 *    `prompt=consent`; Entra v2 rejects `resource`)
 *  - token-form sanitization (resource stripped, secret injected server-side,
 *    scope injected on bare refresh_token grants)
 *  - v2-issuer default with opt-in v1 acceptance (portal-registered apps
 *    default to v1 access tokens until requestedAccessTokenVersion: 2)
 * plus identity→permission mapping (unmapped = deny by default) and the
 * legacy-token passthrough (non-JWT tokens never touch the Entra path).
 */
import { describe, test, expect, beforeAll } from 'bun:test';
import { generateKeyPair, SignJWT } from 'jose';
import {
  resolveEntraConfig,
  looksLikeJwt,
  sanitizeAuthorizeParams,
  sanitizeTokenForm,
  buildAuthServerMetadata,
  buildProtectedResourceMetadata,
  buildRegisterResponse,
  resolveIdentityGrant,
  verifyEntraToken,
  EntraTokenVerifier,
  createEntraAwareVerifier,
  entraScopes,
  type EntraConfig,
} from '../src/core/entra-auth.ts';

const TENANT = '00000000-1111-2222-3333-444444444444';
const CLIENT = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
const V2_ISSUER = `https://login.microsoftonline.com/${TENANT}/v2.0`;
const V1_ISSUER = `https://sts.windows.net/${TENANT}/`;

function mkConfig(overrides: Partial<EntraConfig> = {}): EntraConfig {
  return {
    tenantId: TENANT,
    clientId: CLIENT,
    clientSecret: 'test-secret',
    apiScope: `api://${CLIENT}/access`,
    acceptV1Issuer: false,
    identityMap: new Map([
      ['alice@acme-example.com', { scopes: ['read', 'write'] }],
      ['oid-charlie', { scopes: ['read'], sourceId: 'wiki', federatedRead: ['wiki', 'default'] }],
    ]),
    defaultScopes: [],
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Config resolution
// ---------------------------------------------------------------------------

describe('resolveEntraConfig', () => {
  test('disabled by default (no env, no file) → null', () => {
    expect(resolveEntraConfig(undefined, {})).toBeNull();
    expect(resolveEntraConfig(null, {})).toBeNull();
  });

  test('enabled via env vars', () => {
    const cfg = resolveEntraConfig(undefined, {
      GBRAIN_ENTRA_ENABLED: '1',
      GBRAIN_ENTRA_TENANT_ID: TENANT,
      GBRAIN_ENTRA_CLIENT_ID: CLIENT,
      GBRAIN_ENTRA_CLIENT_SECRET: 's3cret',
    });
    expect(cfg).not.toBeNull();
    expect(cfg!.tenantId).toBe(TENANT);
    expect(cfg!.apiScope).toBe(`api://${CLIENT}/access`); // derived default
    expect(cfg!.acceptV1Issuer).toBe(false); // default OFF
    expect(cfg!.defaultScopes).toEqual([]); // default DENY for unmapped
  });

  test('GBRAIN_ENTRA_ENABLED=0 force-disables a file-enabled config (rollback lever)', () => {
    const file = { enabled: true, tenant_id: TENANT, client_id: CLIENT, client_secret: 'x' };
    expect(resolveEntraConfig(file, { GBRAIN_ENTRA_ENABLED: '0' })).toBeNull();
    expect(resolveEntraConfig(file, {})).not.toBeNull();
  });

  test('enabled but incomplete → throws (fail-loud, not silent native-only)', () => {
    expect(() => resolveEntraConfig({ enabled: true, tenant_id: TENANT }, {}))
      .toThrow(/missing/);
  });

  test('env wins over file plane per key', () => {
    const cfg = resolveEntraConfig(
      { enabled: true, tenant_id: 'file-tenant', client_id: CLIENT, client_secret: 'file-secret' },
      { GBRAIN_ENTRA_TENANT_ID: TENANT },
    );
    expect(cfg!.tenantId).toBe(TENANT);
    expect(cfg!.clientSecret).toBe('file-secret');
  });

  test('identity_map accepts string / array / object shapes; keys lowercased', () => {
    const cfg = resolveEntraConfig({
      enabled: true,
      tenant_id: TENANT,
      client_id: CLIENT,
      client_secret: 'x',
      identity_map: {
        'Alice@Acme-Example.com': 'read write',
        'bob@acme-example.com': ['read'],
        'oid-1234': { scopes: 'read write', source_id: 'wiki', federated_read: ['wiki'] },
      },
    }, {});
    expect(cfg!.identityMap.get('alice@acme-example.com')!.scopes.sort()).toEqual(['read', 'write']);
    expect(cfg!.identityMap.get('bob@acme-example.com')!.scopes).toEqual(['read']);
    const oid = cfg!.identityMap.get('oid-1234')!;
    expect(oid.scopes.sort()).toEqual(['read', 'write']);
    expect(oid.sourceId).toBe('wiki');
    expect(oid.federatedRead).toEqual(['wiki']);
  });

  test('unknown scope in identity_map → throws (ALLOWED_SCOPES allowlist)', () => {
    expect(() => resolveEntraConfig({
      enabled: true, tenant_id: TENANT, client_id: CLIENT, client_secret: 'x',
      identity_map: { 'a@b.c': 'flying-unicorn' },
    }, {})).toThrow(/Unknown scope/);
  });

  test('GBRAIN_ENTRA_IDENTITY_MAP env JSON overrides the file map; bad JSON throws', () => {
    const base = { enabled: true, tenant_id: TENANT, client_id: CLIENT, client_secret: 'x' };
    const cfg = resolveEntraConfig(
      { ...base, identity_map: { 'file@x.y': 'read' } },
      { GBRAIN_ENTRA_IDENTITY_MAP: JSON.stringify({ 'env@x.y': 'read write' }) },
    );
    expect(cfg!.identityMap.has('file@x.y')).toBe(false);
    expect(cfg!.identityMap.get('env@x.y')!.scopes.sort()).toEqual(['read', 'write']);
    expect(() => resolveEntraConfig(base, { GBRAIN_ENTRA_IDENTITY_MAP: '{not json' }))
      .toThrow(/not valid JSON/);
  });

  test('default_scopes: comma/space env form; validated', () => {
    const base = { enabled: true, tenant_id: TENANT, client_id: CLIENT, client_secret: 'x' };
    expect(resolveEntraConfig(base, { GBRAIN_ENTRA_DEFAULT_SCOPES: 'read' })!.defaultScopes)
      .toEqual(['read']);
    expect(() => resolveEntraConfig(base, { GBRAIN_ENTRA_DEFAULT_SCOPES: 'root' }))
      .toThrow(/Unknown scope/);
  });

  test('accept_v1_issuer: file true honored; env override wins both directions', () => {
    const base = { enabled: true, tenant_id: TENANT, client_id: CLIENT, client_secret: 'x' };
    expect(resolveEntraConfig({ ...base, accept_v1_issuer: true }, {})!.acceptV1Issuer).toBe(true);
    expect(resolveEntraConfig({ ...base, accept_v1_issuer: true }, { GBRAIN_ENTRA_ACCEPT_V1_ISSUER: '0' })!.acceptV1Issuer).toBe(false);
    expect(resolveEntraConfig(base, { GBRAIN_ENTRA_ACCEPT_V1_ISSUER: 'true' })!.acceptV1Issuer).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// JWT structural detection
// ---------------------------------------------------------------------------

describe('looksLikeJwt', () => {
  test('native + legacy gbrain tokens are NOT JWTs', () => {
    expect(looksLikeJwt('gbrain_at_0123456789abcdef')).toBe(false);
    expect(looksLikeJwt('gbrain_cafebabe')).toBe(false);
    expect(looksLikeJwt('')).toBe(false);
    expect(looksLikeJwt('a.b')).toBe(false);
    expect(looksLikeJwt('not..ajwt')).toBe(false);
  });

  test('a signed JWT is detected', async () => {
    const { privateKey } = await generateKeyPair('RS256');
    const jwt = await new SignJWT({ x: 1 })
      .setProtectedHeader({ alg: 'RS256' })
      .sign(privateKey);
    expect(looksLikeJwt(jwt)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Authorize-param sanitization (finding 2, authorize side)
// ---------------------------------------------------------------------------

describe('sanitizeAuthorizeParams', () => {
  test('strips resource/prompt/client extras; preserves the whitelist; injects client_id + scope', () => {
    const cfg = mkConfig();
    // Exactly what claude.ai sends, plus its own client_id/scope.
    const incoming = new URLSearchParams({
      response_type: 'code',
      redirect_uri: 'https://claude.ai/api/mcp/auth_callback',
      state: 'st4te',
      code_challenge: 'chall',
      code_challenge_method: 'S256',
      resource: 'https://brain.example.com/mcp', // RFC 8707 — Entra rejects
      prompt: 'consent',
      client_id: 'client-supplied-id',
      scope: 'client-supplied-scope',
      nonce: 'whatever',
    });
    const q = sanitizeAuthorizeParams(incoming, cfg);
    expect(q.get('resource')).toBeNull();
    expect(q.get('prompt')).toBeNull();
    expect(q.get('nonce')).toBeNull();
    expect(q.get('response_type')).toBe('code');
    expect(q.get('redirect_uri')).toBe('https://claude.ai/api/mcp/auth_callback');
    expect(q.get('state')).toBe('st4te');
    expect(q.get('code_challenge')).toBe('chall');
    expect(q.get('code_challenge_method')).toBe('S256');
    // Server-injected, never client-supplied:
    expect(q.get('client_id')).toBe(CLIENT);
    expect(q.get('scope')).toBe(entraScopes(cfg).join(' '));
  });

  test('absent whitelist params are simply omitted', () => {
    const q = sanitizeAuthorizeParams(new URLSearchParams({ response_type: 'code' }), mkConfig());
    expect(q.get('redirect_uri')).toBeNull();
    expect(q.get('state')).toBeNull();
    expect([...q.keys()].sort()).toEqual(['client_id', 'response_type', 'scope']);
  });
});

// ---------------------------------------------------------------------------
// Token-form sanitization (finding 2, token side)
// ---------------------------------------------------------------------------

describe('sanitizeTokenForm', () => {
  test('authorization_code: resource stripped, secret injected, no scope injection', () => {
    const cfg = mkConfig();
    const form = sanitizeTokenForm(new URLSearchParams({
      grant_type: 'authorization_code',
      code: 'abc',
      redirect_uri: 'https://claude.ai/api/mcp/auth_callback',
      code_verifier: 'ver',
      resource: 'https://brain.example.com/mcp', // → 400 AADSTS9010010 if forwarded
      client_id: 'client-supplied',
    }), cfg);
    expect(form.get('resource')).toBeNull();
    expect(form.get('client_id')).toBe(CLIENT); // server value wins
    expect(form.get('client_secret')).toBe('test-secret'); // injected server-side
    expect(form.get('code')).toBe('abc');
    expect(form.get('code_verifier')).toBe('ver');
    expect(form.get('scope')).toBeNull(); // only refresh grants get the injection
  });

  test('refresh_token without scope: full scope string injected', () => {
    const cfg = mkConfig();
    const form = sanitizeTokenForm(new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: 'rt',
      resource: 'https://brain.example.com/mcp',
    }), cfg);
    expect(form.get('resource')).toBeNull();
    expect(form.get('scope')).toBe(entraScopes(cfg).join(' '));
    expect(form.get('client_secret')).toBe('test-secret');
  });

  test('refresh_token with an explicit scope keeps it', () => {
    const form = sanitizeTokenForm(new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: 'rt',
      scope: 'openid',
    }), mkConfig());
    expect(form.get('scope')).toBe('openid');
  });

  test('does not mutate the caller-owned form', () => {
    const incoming = new URLSearchParams({ grant_type: 'refresh_token', resource: 'x' });
    sanitizeTokenForm(incoming, mkConfig());
    expect(incoming.get('resource')).toBe('x');
    expect(incoming.get('client_secret')).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// DCR-shim metadata + register response
// ---------------------------------------------------------------------------

describe('DCR shim metadata', () => {
  test('AS metadata points every endpoint at the server itself', () => {
    const md = buildAuthServerMetadata('https://brain.example.com/', mkConfig());
    expect(md.issuer).toBe('https://brain.example.com');
    expect(md.authorization_endpoint).toBe('https://brain.example.com/oauth/authorize');
    expect(md.token_endpoint).toBe('https://brain.example.com/oauth/token');
    expect(md.registration_endpoint).toBe('https://brain.example.com/oauth/register');
    expect(md.code_challenge_methods_supported).toEqual(['S256']);
    expect(md.token_endpoint_auth_methods_supported).toEqual(['none']);
  });

  test('protected-resource metadata names the server as its own AS', () => {
    const md = buildProtectedResourceMetadata('https://brain.example.com', mkConfig());
    expect(md.resource).toBe('https://brain.example.com/mcp');
    expect(md.authorization_servers).toEqual(['https://brain.example.com']);
  });

  test('register response echoes client metadata and hands out the configured client_id', () => {
    const r = buildRegisterResponse(mkConfig(), {
      client_name: 'claudeai',
      redirect_uris: ['https://claude.ai/api/mcp/auth_callback'],
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
    });
    expect(r.client_id).toBe(CLIENT);
    expect(typeof r.client_id_issued_at).toBe('number');
    expect(r.token_endpoint_auth_method).toBe('none');
    expect(r.client_name).toBe('claudeai');
    expect(r.redirect_uris).toEqual(['https://claude.ai/api/mcp/auth_callback']);
  });

  test('register response defaults for an empty body', () => {
    const r = buildRegisterResponse(mkConfig(), {});
    expect(r.client_name).toBe('claude');
    expect(r.grant_types).toEqual(['authorization_code', 'refresh_token']);
    expect(r.response_types).toEqual(['code']);
    expect(r.redirect_uris).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// JWT verification (local keypair — real jose checks, no JWKS fetch)
// ---------------------------------------------------------------------------

describe('verifyEntraToken', () => {
  let publicKey: CryptoKey;
  let privateKey: CryptoKey;

  beforeAll(async () => {
    const pair = await generateKeyPair('RS256');
    publicKey = pair.publicKey as CryptoKey;
    privateKey = pair.privateKey as CryptoKey;
  });

  function sign(claims: Record<string, unknown> = {}, opts: { issuer?: string; audience?: string; expired?: boolean } = {}) {
    const jwt = new SignJWT({
      preferred_username: 'Alice@Acme-Example.com',
      name: 'Alice Example',
      oid: 'oid-alice',
      tid: TENANT,
      ...claims,
    })
      .setProtectedHeader({ alg: 'RS256' })
      .setIssuer(opts.issuer ?? V2_ISSUER)
      .setAudience(opts.audience ?? CLIENT)
      .setIssuedAt();
    if (opts.expired) jwt.setExpirationTime(Math.floor(Date.now() / 1000) - 60);
    else jwt.setExpirationTime('1h');
    return jwt.sign(privateKey);
  }

  test('valid v2 token from a mapped UPN → AuthInfo with mapped scopes + identity threading', async () => {
    const cfg = mkConfig();
    const token = await sign();
    const auth = await verifyEntraToken(token, cfg, publicKey);
    expect(auth.scopes.sort()).toEqual(['read', 'write']); // UPN matched case-insensitively
    expect(auth.clientId).toBe('entra:oid-alice'); // stable audit id
    expect(auth.clientName).toBe('Alice@Acme-Example.com'); // authorship stamp
    expect(auth.entra?.oid).toBe('oid-alice');
    expect(auth.entra?.name).toBe('Alice Example');
    expect(typeof auth.expiresAt).toBe('number');
    expect(auth.expiresAt!).toBeGreaterThan(Date.now() / 1000);
  });

  test('audience api://<client-id> is accepted too', async () => {
    const token = await sign({}, { audience: `api://${CLIENT}` });
    const auth = await verifyEntraToken(token, mkConfig(), publicKey);
    expect(auth.scopes.length).toBeGreaterThan(0);
  });

  test('wrong issuer → InvalidTokenError', async () => {
    const token = await sign({}, { issuer: 'https://login.microsoftonline.com/some-other-tenant/v2.0' });
    expect(verifyEntraToken(token, mkConfig(), publicKey)).rejects.toThrow(/Entra token rejected/);
  });

  test('wrong audience → InvalidTokenError', async () => {
    const token = await sign({}, { audience: 'some-other-app' });
    expect(verifyEntraToken(token, mkConfig(), publicKey)).rejects.toThrow(/Entra token rejected/);
  });

  test('expired token → InvalidTokenError', async () => {
    const token = await sign({}, { expired: true });
    expect(verifyEntraToken(token, mkConfig(), publicKey)).rejects.toThrow(/Entra token rejected/);
  });

  test('v1 issuer rejected by default (finding 3: requestedAccessTokenVersion)', async () => {
    const token = await sign({}, { issuer: V1_ISSUER });
    expect(verifyEntraToken(token, mkConfig(), publicKey)).rejects.toThrow(/Entra token rejected/);
  });

  test('v1 issuer accepted ONLY with accept_v1_issuer', async () => {
    const token = await sign({}, { issuer: V1_ISSUER });
    const auth = await verifyEntraToken(token, mkConfig({ acceptV1Issuer: true }), publicKey);
    expect(auth.scopes.sort()).toEqual(['read', 'write']);
  });

  test('oid match works when UPN is unmapped; grant source bindings thread through', async () => {
    const token = await sign({ preferred_username: 'charlie@acme-example.com', oid: 'OID-Charlie' });
    const auth = await verifyEntraToken(token, mkConfig(), publicKey);
    expect(auth.scopes).toEqual(['read']);
    expect(auth.sourceId).toBe('wiki');
    expect(auth.allowedSources).toEqual(['wiki', 'default']);
  });

  test('unmapped identity → DENY by default (valid tenant token is not enough)', async () => {
    const token = await sign({ preferred_username: 'mallory@acme-example.com', oid: 'oid-mallory' });
    expect(verifyEntraToken(token, mkConfig(), publicKey)).rejects.toThrow(/not authorized/);
  });

  test('unmapped identity gets default_scopes when configured', async () => {
    const token = await sign({ preferred_username: 'newhire@acme-example.com', oid: 'oid-new' });
    const auth = await verifyEntraToken(token, mkConfig({ defaultScopes: ['read'] }), publicKey);
    expect(auth.scopes).toEqual(['read']);
  });

  test('tampered signature → InvalidTokenError', async () => {
    const { privateKey: otherKey } = await generateKeyPair('RS256');
    const forged = await new SignJWT({ preferred_username: 'alice@acme-example.com', oid: 'oid-alice' })
      .setProtectedHeader({ alg: 'RS256' })
      .setIssuer(V2_ISSUER)
      .setAudience(CLIENT)
      .setIssuedAt()
      .setExpirationTime('1h')
      .sign(otherKey);
    expect(verifyEntraToken(forged, mkConfig(), publicKey)).rejects.toThrow(/Entra token rejected/);
  });
});

// ---------------------------------------------------------------------------
// Identity grant resolution (pure)
// ---------------------------------------------------------------------------

describe('resolveIdentityGrant', () => {
  test('UPN beats oid when both map', () => {
    const cfg = mkConfig({
      identityMap: new Map([
        ['alice@acme-example.com', { scopes: ['admin'] }],
        ['oid-alice', { scopes: ['read'] }],
      ]),
    });
    const grant = resolveIdentityGrant(cfg, { preferred_username: 'alice@acme-example.com', oid: 'oid-alice' });
    expect(grant!.scopes).toEqual(['admin']);
  });

  test('unmapped + empty default → null', () => {
    expect(resolveIdentityGrant(mkConfig(), { preferred_username: 'x@y.z', oid: 'nope' })).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Legacy-token passthrough (both auth paths live simultaneously)
// ---------------------------------------------------------------------------

describe('createEntraAwareVerifier', () => {
  test('non-JWT tokens hit the existing (fallback) path unchanged', async () => {
    const seen: string[] = [];
    const { publicKey } = await generateKeyPair('RS256');
    const verifier = createEntraAwareVerifier(
      new EntraTokenVerifier(mkConfig(), { key: publicKey as CryptoKey }),
      {
        async verifyAccessToken(token: string) {
          seen.push(token);
          return { token, clientId: 'legacy-client', scopes: ['read', 'write', 'admin'], expiresAt: Date.now() / 1000 + 3600 };
        },
      },
    );
    const auth = await verifier.verifyAccessToken('gbrain_at_deadbeef');
    expect(seen).toEqual(['gbrain_at_deadbeef']);
    expect(auth.clientId).toBe('legacy-client');
  });

  test('JWTs route to Entra and never fall through to the legacy path', async () => {
    const seen: string[] = [];
    const { publicKey, privateKey } = await generateKeyPair('RS256');
    const verifier = createEntraAwareVerifier(
      new EntraTokenVerifier(mkConfig(), { key: publicKey as CryptoKey }),
      {
        async verifyAccessToken(token: string) {
          seen.push(token);
          return { token, clientId: 'legacy-client', scopes: [], expiresAt: 0 };
        },
      },
    );
    const good = await new SignJWT({ preferred_username: 'alice@acme-example.com', oid: 'oid-alice' })
      .setProtectedHeader({ alg: 'RS256' })
      .setIssuer(V2_ISSUER).setAudience(CLIENT).setIssuedAt().setExpirationTime('1h')
      .sign(privateKey);
    const auth = await verifier.verifyAccessToken(good);
    expect(auth.clientId).toBe('entra:oid-alice');

    // A BAD JWT is rejected outright — it does not blur into the legacy path.
    const bad = await new SignJWT({ preferred_username: 'alice@acme-example.com' })
      .setProtectedHeader({ alg: 'RS256' })
      .setIssuer('https://evil.example.com').setAudience(CLIENT).setIssuedAt().setExpirationTime('1h')
      .sign(privateKey);
    expect(verifier.verifyAccessToken(bad)).rejects.toThrow(/Entra token rejected/);
    expect(seen).toEqual([]);
  });
});
