import { generateKeyPairSync, verify } from 'crypto';

import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/services/oidcClientRegistry', () => ({
  findActiveOidcClient: vi.fn(),
  getOidcClientResourceScopes: vi.fn(),
}));

vi.mock('../../../src/services/oidcAuthContext', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/services/oidcAuthContext')>()),
  resolveCurrentSession: vi.fn(),
}));

vi.mock('../../../src/services/oidcProviderKeys', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/services/oidcProviderKeys')>()),
  getActiveOidcSigningKey: vi.fn(),
}));

import { getSystemConfig } from '../../../src/config/getSystemConfig';
import { resolveCurrentSession } from '../../../src/services/oidcAuthContext';
import {
  findActiveOidcClient,
  getOidcClientResourceScopes,
} from '../../../src/services/oidcClientRegistry';
import {
  getActiveOidcSigningKey,
  OidcProviderKeysError,
} from '../../../src/services/oidcProviderKeys';
import { signForOidcEdge } from '../../../src/services/oidcSigning';

const ISSUER = 'https://login.example.com';
const SESSION = '11111111-1111-4111-8111-111111111111';
const API = 'https://api.example.com';
const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });

const authTimeDate = new Date('2026-10-30T12:00:00.000Z');
const authTime = Math.floor(authTimeDate.getTime() / 1000);

function b64(value: unknown) {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function input(header: Record<string, unknown>, claims: Record<string, unknown>) {
  return `${b64(header)}.${b64(claims)}`;
}

const now = () => Math.floor(Date.now() / 1000);

function idTokenClaims(overrides: Record<string, unknown> = {}) {
  return {
    iss: ISSUER,
    sub: 'user-1',
    aud: 'app',
    exp: now() + 3600,
    iat: now(),
    acr: 'phrh',
    amr: ['hwk', 'user', 'mfa'],
    auth_time: authTime,
    ...overrides,
  };
}

function idTokenRequest(claims = idTokenClaims(), header: Record<string, unknown> = {}) {
  return {
    kind: 'id_token' as const,
    kid: 'k1',
    clientId: 'app',
    sessionId: SESSION,
    signingInput: input({ alg: 'RS256', kid: 'k1', ...header }, claims),
  };
}

function accessTokenRequest(
  claims: Record<string, unknown> = {},
  header: Record<string, unknown> = {},
) {
  return {
    kind: 'access_token' as const,
    kid: 'k1',
    clientId: 'app',
    sessionId: SESSION,
    signingInput: input(
      { alg: 'RS256', kid: 'k1', typ: 'at+jwt', ...header },
      {
        iss: ISSUER,
        sub: 'user-1',
        aud: API,
        client_id: 'app',
        scope: 'read',
        exp: now() + 600,
        ...claims,
      },
    ),
  };
}

function clientCredentialsRequest(claims: Record<string, unknown> = {}) {
  return {
    kind: 'client_credentials' as const,
    kid: 'k1',
    clientId: 'svc',
    signingInput: input(
      { alg: 'RS256', kid: 'k1', typ: 'at+jwt' },
      {
        iss: ISSUER,
        sub: 'svc',
        client_id: 'svc',
        aud: API,
        scope: 'read',
        exp: now() + 600,
        ...claims,
      },
    ),
  };
}

const passkeySession = {
  id: SESSION,
  userId: 'user-1',
  recovery: false,
  authMethods: [
    { method: 'passkey', at: authTimeDate.toISOString(), deviceBound: true, userVerified: true },
  ],
  authTime: authTimeDate,
  createdAt: authTimeDate,
};

describe('signForOidcEdge', () => {
  beforeEach(() => {
    vi.mocked(getSystemConfig).mockResolvedValue({ oidc_issuer: ISSUER } as never);
    vi.mocked(getActiveOidcSigningKey).mockReturnValue(privateKey);
    vi.mocked(findActiveOidcClient).mockImplementation((async (id: string) => ({
      id,
      grantTypes: id === 'svc' ? ['client_credentials'] : ['authorization_code', 'refresh_token'],
    })) as never);
    vi.mocked(getOidcClientResourceScopes).mockResolvedValue(new Map([[API, new Set(['read'])]]));
    vi.mocked(resolveCurrentSession).mockResolvedValue(passkeySession as never);
  });

  it('signs an ID token whose claims match the session', async () => {
    const request = idTokenRequest();
    const outcome = await signForOidcEdge(request);

    expect(outcome).toMatchObject({ ok: true, kid: 'k1' });
    if (!outcome.ok) throw new Error('expected a signature');
    expect(
      verify(
        'sha256',
        Buffer.from(request.signingInput),
        publicKey,
        Buffer.from(outcome.signature, 'base64url'),
      ),
    ).toBe(true);
  });

  it('signs an ID token that leaves the auth context out', async () => {
    const claims = idTokenClaims();
    delete (claims as Record<string, unknown>).acr;
    delete (claims as Record<string, unknown>).amr;
    delete (claims as Record<string, unknown>).auth_time;

    expect((await signForOidcEdge(idTokenRequest(claims))).ok).toBe(true);
  });

  it('accepts an audience array holding only the client', async () => {
    expect((await signForOidcEdge(idTokenRequest(idTokenClaims({ aud: ['app'] })))).ok).toBe(true);
  });

  it('falls back to createdAt for auth_time', async () => {
    vi.mocked(resolveCurrentSession).mockResolvedValue({
      ...passkeySession,
      authTime: null,
      authMethods: undefined,
    } as never);

    const claims = idTokenClaims({ acr: undefined, amr: [] });
    expect((await signForOidcEdge(idTokenRequest(claims))).ok).toBe(true);
  });

  it.each([
    ['an undecodable header', { signingInput: '!!!.e30' }],
    ['a non-object payload', { signingInput: `${b64({ alg: 'RS256', kid: 'k1' })}.${b64([1])}` }],
    ['another algorithm', idTokenRequest(idTokenClaims(), { alg: 'HS256' })],
    ['a header kid that differs', idTokenRequest(idTokenClaims(), { kid: 'k2' })],
    ['an extra header member', idTokenRequest(idTokenClaims(), { jku: 'https://evil.example' })],
    ['no expiry', idTokenRequest(idTokenClaims({ exp: undefined }))],
    ['an expired token', idTokenRequest(idTokenClaims({ exp: now() - 1 }))],
    ['too long a lifetime', idTokenRequest(idTokenClaims({ exp: now() + 60 * 60 * 25 }))],
    ['an ID token typed as an access token', idTokenRequest(idTokenClaims(), { typ: 'at+jwt' })],
    ['an access token without at+jwt', accessTokenRequest({}, { typ: undefined })],
  ])('refuses %s as malformed', async (_label, overrides) => {
    const outcome = await signForOidcEdge({ ...idTokenRequest(), ...overrides });
    expect(outcome).toEqual({ ok: false, code: 'malformed_signing_input' });
  });

  it('refuses a key that is not the active one', async () => {
    vi.mocked(getActiveOidcSigningKey).mockReturnValue(null);
    expect(await signForOidcEdge(idTokenRequest())).toEqual({ ok: false, code: 'unknown_key' });
  });

  it('refuses when the provider keys are not configured', async () => {
    vi.mocked(getActiveOidcSigningKey).mockImplementation(() => {
      throw new OidcProviderKeysError('missing');
    });
    expect(await signForOidcEdge(idTokenRequest())).toEqual({ ok: false, code: 'unknown_key' });
  });

  it('rethrows an unexpected key error', async () => {
    vi.mocked(getActiveOidcSigningKey).mockImplementation(() => {
      throw new Error('boom');
    });
    await expect(signForOidcEdge(idTokenRequest())).rejects.toThrow('boom');
  });

  it('refuses another issuer, and any issuer when none is configured', async () => {
    expect(await signForOidcEdge(idTokenRequest(idTokenClaims({ iss: API })))).toEqual({
      ok: false,
      code: 'issuer_mismatch',
    });

    vi.mocked(getSystemConfig).mockResolvedValue({ oidc_issuer: null } as never);
    expect((await signForOidcEdge(idTokenRequest())) as { code: string }).toMatchObject({
      code: 'issuer_mismatch',
    });
  });

  it('refuses an inactive client', async () => {
    vi.mocked(findActiveOidcClient).mockResolvedValue(null);
    expect(await signForOidcEdge(idTokenRequest())).toEqual({ ok: false, code: 'client_inactive' });
  });

  it('refuses a user token for a client without a user grant', async () => {
    vi.mocked(findActiveOidcClient).mockResolvedValue({
      id: 'app',
      grantTypes: ['client_credentials'],
    } as never);
    expect(await signForOidcEdge(idTokenRequest())).toEqual({
      ok: false,
      code: 'grant_not_allowed',
    });
  });

  it('refuses a revoked session, or none at all', async () => {
    vi.mocked(resolveCurrentSession).mockResolvedValue(null);
    expect(await signForOidcEdge(idTokenRequest())).toEqual({ ok: false, code: 'session_revoked' });
    expect(await signForOidcEdge({ ...idTokenRequest(), sessionId: undefined })).toEqual({
      ok: false,
      code: 'session_revoked',
    });
  });

  it('refuses a token for another user', async () => {
    expect(await signForOidcEdge(idTokenRequest(idTokenClaims({ sub: 'user-2' })))).toEqual({
      ok: false,
      code: 'subject_mismatch',
      userId: 'user-1',
    });
  });

  it('refuses a recovery session', async () => {
    vi.mocked(resolveCurrentSession).mockResolvedValue({
      ...passkeySession,
      recovery: true,
    } as never);
    expect(await signForOidcEdge(idTokenRequest())).toMatchObject({
      code: 'auth_context_mismatch',
    });
  });

  it.each([
    ['a raised acr', { acr: 'phrh' }, { deviceBound: false }],
    ['an acr the session never earned', { acr: 'phr' }, { userVerified: false }],
    ['an amr that differs', { amr: ['hwk', 'user'] }, {}],
    ['an amr that is not a list', { amr: 'hwk' }, {}],
    ['another auth_time', { auth_time: authTime - 60 }, {}],
  ])('refuses %s', async (_label, claims, passkey) => {
    vi.mocked(resolveCurrentSession).mockResolvedValue({
      ...passkeySession,
      authMethods: [{ ...passkeySession.authMethods[0], ...passkey }],
    } as never);

    const base = idTokenClaims({ amr: undefined, acr: undefined });
    expect(await signForOidcEdge(idTokenRequest({ ...base, ...claims }))).toMatchObject({
      code: 'auth_context_mismatch',
    });
  });

  it('refuses an ID token for another audience', async () => {
    for (const aud of ['other', ['app', 'other']]) {
      expect(await signForOidcEdge(idTokenRequest(idTokenClaims({ aud })))).toMatchObject({
        code: 'audience_mismatch',
      });
    }
  });

  it('signs a user access token for a linked resource and scope', async () => {
    expect((await signForOidcEdge(accessTokenRequest())).ok).toBe(true);
  });

  it('refuses a user access token for another client', async () => {
    expect(await signForOidcEdge(accessTokenRequest({ client_id: 'other' }))).toMatchObject({
      code: 'audience_mismatch',
    });
  });

  it('refuses an access token for an unlinked resource or a non-string audience', async () => {
    expect(
      await signForOidcEdge(accessTokenRequest({ aud: 'https://other.example' })),
    ).toMatchObject({ code: 'audience_mismatch' });
    expect(await signForOidcEdge(accessTokenRequest({ aud: [API] }))).toMatchObject({
      code: 'audience_mismatch',
    });
  });

  it('refuses scopes the link does not allow', async () => {
    expect(await signForOidcEdge(accessTokenRequest({ scope: 'read write' }))).toMatchObject({
      code: 'grant_not_allowed',
    });
  });

  it('treats a missing scope claim as no scopes', async () => {
    expect((await signForOidcEdge(accessTokenRequest({ scope: undefined }))).ok).toBe(true);
  });

  it('signs a client credentials token for an allowed client', async () => {
    expect((await signForOidcEdge(clientCredentialsRequest())).ok).toBe(true);
  });

  it('refuses a client credentials token naming another subject', async () => {
    expect(await signForOidcEdge(clientCredentialsRequest({ sub: 'user-1' }))).toEqual({
      ok: false,
      code: 'subject_mismatch',
    });
  });

  it('refuses client credentials for a client without the grant', async () => {
    vi.mocked(findActiveOidcClient).mockResolvedValue({
      id: 'svc',
      grantTypes: ['authorization_code'],
    } as never);
    expect(await signForOidcEdge(clientCredentialsRequest())).toEqual({
      ok: false,
      code: 'grant_not_allowed',
    });
  });

  it('refuses client credentials for an unlinked resource', async () => {
    vi.mocked(getOidcClientResourceScopes).mockResolvedValue(new Map());
    expect(await signForOidcEdge(clientCredentialsRequest())).toEqual({
      ok: false,
      code: 'audience_mismatch',
    });
  });
});
