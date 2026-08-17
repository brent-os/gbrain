/**
 * whoami op contract tests — pins the v0.28 transport-detection shape.
 *
 * The test surface is the op's handler called against synthesized
 * OperationContext rather than the full HTTP stack — keeps the test pure
 * and fast. End-to-end coverage (real HTTP MCP) lives in
 * test/e2e/serve-http-oauth.test.ts and test/e2e/sources-remote-mcp.test.ts.
 */

import { test, expect, describe } from 'bun:test';
import { operations, OperationError } from '../src/core/operations.ts';
import type { OperationContext, AuthInfo } from '../src/core/operations.ts';

const whoami = operations.find(o => o.name === 'whoami')!;

function ctxWith(overrides: Partial<OperationContext>): OperationContext {
  // Shape exposes only what whoami reads. Every required field gets a
  // safe stub; the test-relevant overrides come last to win.
  return {
    engine: {} as any,
    config: {} as any,
    logger: { info() {}, warn() {}, error() {} },
    dryRun: false,
    remote: true, // default for tests; specific cases override
    ...overrides,
  } as OperationContext;
}

describe('whoami op contract', () => {
  test('local transport (ctx.remote === false) returns empty scopes', async () => {
    const result = (await whoami.handler(
      ctxWith({ remote: false }),
      {},
    )) as any;
    expect(result.transport).toBe('local');
    expect(result.scopes).toEqual([]);
  });

  test('local transport ignores ctx.auth even if a stale value leaked through', async () => {
    // Defense in depth: even if some buggy transport set both remote=false
    // AND a stale auth blob, the local return shape stays explicit.
    const result = (await whoami.handler(
      ctxWith({
        remote: false,
        auth: {
          token: 'x',
          clientId: 'gbrain_cl_123',
          scopes: ['admin'],
          expiresAt: 999999,
        } as AuthInfo,
      }),
      {},
    )) as any;
    expect(result.transport).toBe('local');
    expect(result.scopes).toEqual([]);
  });

  test('oauth transport returns client identity and exact source grants', async () => {
    const auth: AuthInfo = {
      token: 'gbrain_at_xxx',
      clientId: 'gbrain_cl_abc',
      clientName: 'gstack-test',
      scopes: ['read', 'sources_admin'],
      expiresAt: 1234567890,
      sourceId: 'hot-memory',
      allowedSources: ['hot-memory', 'canonical-brain'],
    };
    const result = (await whoami.handler(
      ctxWith({ remote: true, sourceId: 'transport-fallback', auth }),
      {},
    )) as any;
    expect(result).toEqual({
      transport: 'oauth',
      client_id: 'gbrain_cl_abc',
      client_name: 'gstack-test',
      scopes: ['read', 'sources_admin'],
      expires_at: 1234567890,
      source_id: 'hot-memory',
      federated_read: ['hot-memory', 'canonical-brain'],
    });
  });

  test('oauth transport uses fail-closed empty values when source grants are absent', async () => {
    const auth: AuthInfo = {
      token: 'gbrain_at_pre_migration',
      clientId: 'gbrain_cl_pre_migration',
      scopes: ['read'],
    };
    const result = (await whoami.handler(
      ctxWith({ remote: true, sourceId: 'transport-fallback', auth }),
      {},
    )) as any;
    expect(result.source_id).toBeNull();
    expect(result.federated_read).toEqual([]);
  });

  test('oauth transport preserves an explicit empty federated grant', async () => {
    const auth: AuthInfo = {
      token: 'gbrain_at_empty',
      clientId: 'gbrain_cl_empty',
      scopes: ['read', 'write'],
      sourceId: 'hot-memory',
      allowedSources: [],
    };
    const result = (await whoami.handler(
      ctxWith({ remote: true, auth }),
      {},
    )) as any;
    expect(result.source_id).toBe('hot-memory');
    expect(result.federated_read).toEqual([]);
  });

  test('oauth transport does not widen federated_read with the write source', async () => {
    const auth: AuthInfo = {
      token: 'gbrain_at_narrow',
      clientId: 'gbrain_cl_narrow',
      scopes: ['read', 'write'],
      sourceId: 'hot-memory',
      allowedSources: ['canonical-brain'],
    };
    const result = (await whoami.handler(
      ctxWith({ remote: true, auth }),
      {},
    )) as any;
    expect(result.source_id).toBe('hot-memory');
    expect(result.federated_read).toEqual(['canonical-brain']);
  });

  // Entra JWT callers (v0.44.2.0 feature) have clientId 'entra:<oid>' — no
  // 'gbrain_cl_' prefix — so before the ctx.auth.entra check (v0.44.3.0)
  // they misfiled into the legacy branch as {transport: 'legacy',
  // expires_at: null}, which cost a debugging session on 2026-08-16.
  test('entra transport returns verified claims, live expiry, and grants', async () => {
    const auth: AuthInfo = {
      token: 'eyJ.entra.jwt',
      clientId: 'entra:00000000-aaaa-bbbb-cccc-000000000001',
      clientName: 'brent@buildcapitalpartners.com',
      scopes: ['read', 'write', 'admin'],
      expiresAt: 1786950000,
      sourceId: 'default',
      allowedSources: ['default'],
      entra: {
        oid: '00000000-aaaa-bbbb-cccc-000000000001',
        preferredUsername: 'brent@buildcapitalpartners.com',
        name: 'Brent Jacobsen',
        tid: 'tenant-guid',
      },
    };
    const result = (await whoami.handler(ctxWith({ remote: true, auth }), {})) as any;
    expect(result).toEqual({
      transport: 'entra',
      client_id: 'entra:00000000-aaaa-bbbb-cccc-000000000001',
      upn: 'brent@buildcapitalpartners.com',
      oid: '00000000-aaaa-bbbb-cccc-000000000001',
      name: 'Brent Jacobsen',
      scopes: ['read', 'write', 'admin'],
      expires_at: 1786950000,
      source_id: 'default',
      federated_read: ['default'],
      write_prefixes: [],
      masked_areas_hidden: false,
    });
  });

  test('entra transport is not mislabeled legacy (the v0.44.2.0 regression)', async () => {
    const auth: AuthInfo = {
      token: 'eyJ.entra.jwt',
      clientId: 'entra:some-oid',
      scopes: ['read'],
      expiresAt: 1786950000,
      entra: { oid: 'some-oid' },
    };
    const result = (await whoami.handler(ctxWith({ remote: true, auth }), {})) as any;
    expect(result.transport).toBe('entra');
    // Live expiry survives — the legacy branch would null it.
    expect(result.expires_at).toBe(1786950000);
  });

  test('entra transport fail-closed nulls for absent optional claims', async () => {
    const auth: AuthInfo = {
      token: 'eyJ.entra.jwt',
      // verifyEntraToken emits oid '' when the claim is absent; whoami
      // surfaces that as null rather than an empty string.
      clientId: 'entra:user@example.com',
      scopes: ['read'],
      expiresAt: 1786950000,
      entra: { oid: '', preferredUsername: 'user@example.com' },
    };
    const result = (await whoami.handler(ctxWith({ remote: true, auth }), {})) as any;
    expect(result.oid).toBeNull();
    expect(result.name).toBeNull();
    expect(result.source_id).toBeNull();
    expect(result.federated_read).toEqual([]);
    expect(result.write_prefixes).toEqual([]);
    expect(result.masked_areas_hidden).toBe(false);
  });

  test('entra masked_areas_hidden is a bare boolean that never names prefixes', async () => {
    // Existence-hiding contract (feature/identity-acl): whoami must reveal
    // THAT areas are hidden, never WHICH — a masked caller could otherwise
    // enumerate the restricted tree from its own introspection.
    const auth: AuthInfo = {
      token: 'eyJ.entra.jwt',
      clientId: 'entra:masked-user',
      scopes: ['read', 'write'],
      expiresAt: 1786950000,
      entra: { oid: 'masked-user' },
      hiddenSlugPrefixes: ['restricted/'],
    };
    const result = (await whoami.handler(ctxWith({ remote: true, auth }), {})) as any;
    expect(result.masked_areas_hidden).toBe(true);
    expect(JSON.stringify(result)).not.toContain('restricted');
  });

  test('entra claims win over prefix sniffing even with a gbrain_cl_ clientId', async () => {
    // Defense in depth: if a future verifier ever sets entra claims on a
    // token whose clientId carries the native prefix, the verified identity
    // is the truth — claim presence outranks string sniffing.
    const auth: AuthInfo = {
      token: 'x',
      clientId: 'gbrain_cl_shadow',
      scopes: ['read'],
      expiresAt: 1,
      entra: { oid: 'real-oid' },
    };
    const result = (await whoami.handler(ctxWith({ remote: true, auth }), {})) as any;
    expect(result.transport).toBe('entra');
  });

  test('legacy transport (token name as clientId, no gbrain_cl_ prefix)', async () => {
    const auth: AuthInfo = {
      token: 'legacy-token',
      clientId: 'my-personal-token',
      clientName: 'my-personal-token',
      scopes: ['read', 'write', 'admin'],
      // Legacy tokens have a synthetic 1y expiry — whoami exposes null
      // since legacy tokens don't actually expire.
      expiresAt: 999999999,
    };
    const result = (await whoami.handler(
      ctxWith({ remote: true, auth }),
      {},
    )) as any;
    expect(result.transport).toBe('legacy');
    expect(result.token_name).toBe('my-personal-token');
    expect(result.scopes).toEqual(['read', 'write', 'admin']);
    expect(result.expires_at).toBeNull();
  });

  // #1061: stdio MCP is remote/untrusted by design but has no per-token auth
  // (local pipe). The stdio dispatch marks ctx.transport='stdio'; whoami
  // reports it instead of throwing unknown_transport.
  test('stdio transport (remote=true, no auth, transport marker) reports stdio', async () => {
    const result = (await whoami.handler(
      ctxWith({ remote: true, auth: undefined, transport: 'stdio' }),
      {},
    )) as any;
    expect(result.transport).toBe('stdio');
    expect(result.scopes).toEqual([]);
  });

  test('stdio marker does not mask real auth (auth still wins)', async () => {
    const result = (await whoami.handler(
      ctxWith({
        remote: true,
        transport: 'stdio',
        auth: {
          token: 'gbrain_at_xxx',
          clientId: 'gbrain_cl_abc',
          scopes: ['read'],
          expiresAt: 1,
        } as AuthInfo,
      }),
      {},
    )) as any;
    expect(result.transport).toBe('oauth');
  });

  // Q3: ambiguous transport — fail-closed. The footgun this guards against
  // is a future transport that lands without threading auth, where a buggy
  // caller might trust whoami's output to gate sensitive ops.
  test('unknown_transport throws when remote=true AND auth is missing', async () => {
    try {
      await whoami.handler(ctxWith({ remote: true, auth: undefined }), {});
      throw new Error('expected throw');
    } catch (e) {
      expect(e).toBeInstanceOf(OperationError);
      expect((e as OperationError).message).toMatch(/unknown_transport|did not thread/);
    }
  });

  test('unknown_transport throws when remote is undefined (cast bypass guard)', async () => {
    // F7b contract: ctx.remote is REQUIRED. If a caller widens the type to
    // Partial<> and passes through undefined, whoami should treat it as
    // remote (the fail-closed default) and throw because auth is missing.
    try {
      await whoami.handler(ctxWith({ remote: undefined as any, auth: undefined }), {});
      throw new Error('expected throw');
    } catch (e) {
      expect(e).toBeInstanceOf(OperationError);
    }
  });
});

describe('whoami op metadata', () => {
  test('description documents OAuth source grant fields', () => {
    expect(whoami.description).toContain('source_id');
    expect(whoami.description).toContain('federated_read');
  });

  test('description documents the entra transport shape', () => {
    expect(whoami.description).toContain('"entra"');
    expect(whoami.description).toContain('upn');
    expect(whoami.description).toContain('oid');
    expect(whoami.description).toContain('masked_areas_hidden');
  });

  test('scope is read (any authenticated caller can introspect itself)', () => {
    expect(whoami.scope).toBe('read');
  });

  test('not localOnly (must work over HTTP MCP for gstack /setup-gbrain)', () => {
    expect(whoami.localOnly).toBeFalsy();
  });

  test('mutating is false', () => {
    expect(whoami.mutating).toBeFalsy();
  });
});
