import { generateKeyPairSync, verify } from 'crypto';

import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/services/oidcClientRegistry', () => ({
  findActiveOidcClient: vi.fn(),
  getOidcClientResourceScopes: vi.fn(),
}));

vi.mock('../../../src/services/oidcAccountClaims', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/services/oidcAccountClaims')>()),
  getOidcAccountClaims: vi.fn(),
}));

vi.mock('../../../src/services/oidcPayloadStore', () => ({
  hasOidcGrantForSession: vi.fn(),
  recordSessionExchangeToken: vi.fn(),
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
import { Session } from '../../../src/models/sessions';
import { getOidcAccountClaims } from '../../../src/services/oidcAccountClaims';
import { resolveCurrentSession } from '../../../src/services/oidcAuthContext';
import {
  findActiveOidcClient,
  getOidcClientResourceScopes,
} from '../../../src/services/oidcClientRegistry';
import {
  hasOidcGrantForSession,
  recordSessionExchangeToken,
} from '../../../src/services/oidcPayloadStore';
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
    grantType: 'authorization_code' as const,
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
    grantType: 'authorization_code' as const,
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
  expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24),
};

describe('signForOidcEdge', () => {
  beforeEach(() => {
    vi.mocked(getSystemConfig).mockResolvedValue({
      oidc_issuer: ISSUER,
      session_idle_ttl: '8h',
    } as never);
    vi.mocked(getActiveOidcSigningKey).mockReturnValue(privateKey);
    vi.mocked(findActiveOidcClient).mockImplementation((async (id: string) => ({
      id,
      grantTypes: id === 'svc' ? ['client_credentials'] : ['authorization_code', 'refresh_token'],
    })) as never);
    vi.mocked(getOidcClientResourceScopes).mockResolvedValue(new Map([[API, new Set(['read'])]]));
    vi.mocked(resolveCurrentSession).mockResolvedValue(passkeySession as never);
    vi.mocked(hasOidcGrantForSession).mockResolvedValue(true);
    vi.mocked(getOidcAccountClaims).mockResolvedValue({
      sub: 'user-1',
      email: 'a@example.com',
      email_verified: true,
      roles: ['user'],
      org_id: null,
      permissions: [],
      customClaims: {},
    });
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

  it('counts a signed user token as activity, up to the absolute lifetime', async () => {
    await signForOidcEdge(idTokenRequest());

    const [values, options] = vi.mocked(Session.update).mock.calls[0] as unknown as [
      { lastUsedAt: Date; idleExpiresAt: Date },
      { where: { id: string } },
    ];
    expect(options).toEqual({ where: { id: SESSION } });
    expect(values.idleExpiresAt.getTime()).toBeGreaterThan(Date.now() + 1000 * 60 * 60 * 7);

    const endsSoon = new Date(Date.now() + 60_000);
    vi.mocked(resolveCurrentSession).mockResolvedValue({
      ...passkeySession,
      expiresAt: endsSoon,
    } as never);
    vi.mocked(getSystemConfig).mockResolvedValue({ oidc_issuer: ISSUER } as never);
    await signForOidcEdge(idTokenRequest());

    const capped = vi.mocked(Session.update).mock.calls[1][0] as { idleExpiresAt: Date };
    expect(capped.idleExpiresAt).toEqual(endsSoon);
  });

  it('skips the activity write when the session ended mid-request', async () => {
    vi.mocked(resolveCurrentSession)
      .mockResolvedValueOnce(passkeySession as never)
      .mockResolvedValueOnce(null);

    expect((await signForOidcEdge(idTokenRequest())).ok).toBe(true);
    expect(Session.update).not.toHaveBeenCalled();
  });

  it('records no session activity for client credentials', async () => {
    await signForOidcEdge(clientCredentialsRequest());
    expect(Session.update).not.toHaveBeenCalled();
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

  it('falls back to the chain start, then createdAt, for auth_time', async () => {
    const chainStartedAt = new Date('2026-10-30T11:00:00.000Z');
    vi.mocked(resolveCurrentSession).mockResolvedValue({
      ...passkeySession,
      authTime: null,
      authMethods: [],
      chainStartedAt,
      createdAt: new Date(),
    } as never);

    const chained = idTokenClaims({
      acr: undefined,
      amr: [],
      auth_time: Math.floor(chainStartedAt.getTime() / 1000),
    });
    expect((await signForOidcEdge(idTokenRequest(chained))).ok).toBe(true);
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

  it('signs identity claims that match the account', async () => {
    const claims = idTokenClaims({
      email: 'a@example.com',
      email_verified: true,
      roles: ['user'],
      org_id: null,
    });
    expect((await signForOidcEdge(idTokenRequest(claims))).ok).toBe(true);
  });

  it.each([
    ['another email', { email: 'victim@example.com' }],
    ['a raised verification', { email_verified: false, phone_number: '+1' }],
    ['other roles', { roles: ['admin'] }],
  ])('refuses identity claims with %s', async (_label, identity) => {
    expect(await signForOidcEdge(idTokenRequest(idTokenClaims(identity)))).toMatchObject({
      code: 'subject_mismatch',
    });
  });

  it('refuses identity claims for an account that no longer exists', async () => {
    vi.mocked(getOidcAccountClaims).mockResolvedValue(null);
    expect(
      await signForOidcEdge(idTokenRequest(idTokenClaims({ email: 'a@example.com' }))),
    ).toMatchObject({ code: 'subject_mismatch' });
  });

  it('refuses a claim the library does not put in that token', async () => {
    expect(await signForOidcEdge(idTokenRequest(idTokenClaims({ 'is-admin': true })))).toEqual({
      ok: false,
      code: 'malformed_signing_input',
    });
    expect(await signForOidcEdge(clientCredentialsRequest({ email: 'a@example.com' }))).toEqual({
      ok: false,
      code: 'malformed_signing_input',
    });
  });

  describe('authorization and custom claims (seamless-auth-oidc-provider#47)', () => {
    const account = {
      sub: 'user-1',
      email: 'a@example.com',
      email_verified: true,
      roles: ['user'],
      org_id: 'org-1',
      permissions: ['orders:read'],
      org_roles: ['member'],
      org_permissions: ['projects:read'],
      customClaims: { tier: 'gold', limits: { seats: 5, regions: ['us', 'eu'] } },
    };
    const carried = {
      roles: ['user'],
      org_id: 'org-1',
      permissions: ['orders:read'],
      org_roles: ['member'],
      org_permissions: ['projects:read'],
      tier: 'gold',
      limits: { seats: 5, regions: ['us', 'eu'] },
    };

    beforeEach(() => {
      vi.mocked(getOidcAccountClaims).mockResolvedValue(account);
    });

    it('signs the values the API computes for the session and client', async () => {
      expect((await signForOidcEdge(idTokenRequest(idTokenClaims(carried)))).ok).toBe(true);
      expect((await signForOidcEdge(accessTokenRequest(carried))).ok).toBe(true);
      expect(getOidcAccountClaims).toHaveBeenCalledWith(
        expect.objectContaining({ id: SESSION, userId: 'user-1' }),
        'app',
      );
    });

    it('compares custom values whatever their key order', async () => {
      const reordered = { ...carried, limits: { regions: ['us', 'eu'], seats: 5 } };
      expect((await signForOidcEdge(idTokenRequest(idTokenClaims(reordered)))).ok).toBe(true);
    });

    it('signs either set alone, and neither', async () => {
      const { tier: _tier, limits: _limits, ...permissionsOnly } = carried;
      expect((await signForOidcEdge(idTokenRequest(idTokenClaims(permissionsOnly)))).ok).toBe(true);
      const customOnly = { tier: 'gold', limits: carried.limits };
      expect((await signForOidcEdge(accessTokenRequest(customOnly))).ok).toBe(true);
      expect((await signForOidcEdge(idTokenRequest())).ok).toBe(true);
    });

    it.each([
      ['a forged custom value', { tier: 'platinum' }],
      ['a forged nested custom value', { limits: { seats: 500, regions: ['us', 'eu'] } }],
      ['an extra permission', { permissions: ['orders:read', 'orders:write'] }],
      ['another organization', { org_id: 'org-2' }],
      ['raised organization roles', { org_roles: ['owner'] }],
      ['the omission marker the API did not set', { permissions_omitted: true }],
    ])('refuses %s', async (_label, forged) => {
      expect(
        await signForOidcEdge(idTokenRequest(idTokenClaims({ ...carried, ...forged }))),
      ).toEqual({ ok: false, code: 'subject_mismatch', userId: 'user-1' });
      expect(await signForOidcEdge(accessTokenRequest({ ...carried, ...forged }))).toEqual({
        ok: false,
        code: 'subject_mismatch',
        userId: 'user-1',
      });
    });

    it('refuses a custom claim name the API did not compute', async () => {
      expect(
        await signForOidcEdge(idTokenRequest(idTokenClaims({ ...carried, is_admin: true }))),
      ).toEqual({ ok: false, code: 'malformed_signing_input', userId: 'user-1' });
    });

    it.each(['act', 'may_act', 'name', 'recovery', 'seamless_admin', 'org_tier', 'Tier'])(
      'refuses the reserved or unlisted name %s before reading the account',
      async (name) => {
        vi.mocked(getOidcAccountClaims).mockResolvedValue({
          ...account,
          customClaims: { ...account.customClaims, [name]: true },
        });
        expect(await signForOidcEdge(idTokenRequest(idTokenClaims({ [name]: true })))).toEqual({
          ok: false,
          code: 'malformed_signing_input',
        });
        expect(getOidcAccountClaims).not.toHaveBeenCalled();
      },
    );

    it.each([
      ['permissions without the organization claims', { org_roles: undefined }],
      ['part of the custom claims', { limits: undefined }],
    ])('refuses %s, since a partial set looks complete', async (_label, dropped) => {
      const claims = { ...carried, ...dropped };
      expect(await signForOidcEdge(accessTokenRequest(JSON.parse(JSON.stringify(claims))))).toEqual(
        { ok: false, code: 'subject_mismatch', userId: 'user-1' },
      );
    });

    it('signs the omission marker when the API omitted permissions, and refuses the lists', async () => {
      vi.mocked(getOidcAccountClaims).mockResolvedValue({
        sub: 'user-1',
        roles: ['user'],
        org_id: 'org-1',
        permissions_omitted: true,
        customClaims: { tier: 'gold' },
      });
      expect(
        (await signForOidcEdge(accessTokenRequest({ permissions_omitted: true, tier: 'gold' }))).ok,
      ).toBe(true);
      expect(
        await signForOidcEdge(accessTokenRequest({ permissions: ['orders:read'], tier: 'gold' })),
      ).toMatchObject({ code: 'subject_mismatch' });
    });

    it('refuses custom claims on a client credentials token', async () => {
      expect(await signForOidcEdge(clientCredentialsRequest({ tier: 'gold' }))).toEqual({
        ok: false,
        code: 'malformed_signing_input',
      });
      expect(await signForOidcEdge(clientCredentialsRequest({ permissions: [] }))).toEqual({
        ok: false,
        code: 'malformed_signing_input',
      });
    });
  });

  it('accepts an ID token typed JWT and refuses any other typ', async () => {
    expect((await signForOidcEdge(idTokenRequest(idTokenClaims(), { typ: 'JWT' }))).ok).toBe(true);
    expect(await signForOidcEdge(idTokenRequest(idTokenClaims(), { typ: 'logout+jwt' }))).toEqual({
      ok: false,
      code: 'malformed_signing_input',
    });
  });

  describe('device-flow tokens (ADR 0001, D10)', () => {
    const DEVICE = 'urn:ietf:params:oauth:grant-type:device_code' as const;

    function deviceClient(overrides: Record<string, unknown> = {}) {
      vi.mocked(findActiveOidcClient).mockResolvedValue({
        id: 'app',
        grantTypes: [DEVICE, 'refresh_token'],
        firstParty: true,
        deviceFlowEnabled: true,
        ...overrides,
      } as never);
    }

    it('signs one that leaves acr, amr and auth_time out', async () => {
      deviceClient();
      const { acr: _acr, amr: _amr, auth_time: _authTime, ...claims } = idTokenClaims();
      expect((await signForOidcEdge({ ...idTokenRequest(claims), grantType: DEVICE })).ok).toBe(
        true,
      );
    });

    it('never signs the amr or auth_time of the approving session', async () => {
      deviceClient();
      const { acr: _acr, ...withAmr } = idTokenClaims();
      const { auth_time: _authTime, ...amrOnly } = withAmr;
      const { amr: _amr, ...authTimeOnly } = withAmr;
      for (const claims of [amrOnly, authTimeOnly]) {
        expect(
          await signForOidcEdge({ ...idTokenRequest(claims), grantType: DEVICE }),
        ).toMatchObject({ ok: false, code: 'auth_context_mismatch' });
      }
    });

    it('never signs the acr the approving session earned', async () => {
      deviceClient();
      expect(await signForOidcEdge({ ...idTokenRequest(), grantType: DEVICE })).toMatchObject({
        ok: false,
        code: 'auth_context_mismatch',
      });
      expect(
        await signForOidcEdge({ ...accessTokenRequest({ acr: 'phrh' }), grantType: DEVICE }),
      ).toMatchObject({ code: 'auth_context_mismatch' });
    });

    it('refuses a client without the device grant turned on', async () => {
      const { acr: _acr, ...claims } = idTokenClaims();
      const request = { ...idTokenRequest(claims), grantType: DEVICE };
      expect(await signForOidcEdge(request)).toMatchObject({ code: 'grant_not_allowed' });

      deviceClient({ deviceFlowEnabled: false });
      expect(await signForOidcEdge(request)).toMatchObject({ code: 'grant_not_allowed' });

      deviceClient({ firstParty: false });
      expect(await signForOidcEdge(request)).toMatchObject({ code: 'grant_not_allowed' });
    });

    it('refuses a user token that names no grant, or one the client lacks', async () => {
      deviceClient();
      expect(await signForOidcEdge(idTokenRequest())).toMatchObject({
        code: 'grant_not_allowed',
      });
      const { grantType: _grant, ...unnamed } = idTokenRequest();
      expect(await signForOidcEdge(unnamed as never)).toMatchObject({
        code: 'grant_not_allowed',
      });
    });
  });

  it('refuses a session with no provider grant for this client', async () => {
    vi.mocked(hasOidcGrantForSession).mockResolvedValue(false);
    expect(await signForOidcEdge(idTokenRequest())).toMatchObject({ code: 'grant_not_allowed' });
    expect(hasOidcGrantForSession).toHaveBeenCalledWith(SESSION, 'app');
  });

  it('refuses an access token whose audience is the provider or the API', async () => {
    vi.stubEnv('ISSUER', 'https://auth.example.com');
    vi.mocked(getOidcClientResourceScopes).mockResolvedValue(
      new Map([
        [ISSUER, new Set(['read'])],
        ['https://auth.example.com', new Set(['read'])],
      ]),
    );

    for (const aud of [ISSUER, `${ISSUER}/`, 'https://auth.example.com']) {
      expect(await signForOidcEdge(accessTokenRequest({ aud }))).toMatchObject({
        code: 'audience_mismatch',
      });
    }
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

describe('a session:exchange token', () => {
  const BUILT_IN = `${ISSUER}/seamless`;
  const DEVICE = 'urn:ietf:params:oauth:grant-type:device_code';

  function exchangeRequest(claims: Record<string, unknown> = {}, grantType = 'authorization_code') {
    const issuedAt = now();
    return {
      kind: 'access_token' as const,
      kid: 'k1',
      clientId: 'cli',
      sessionId: SESSION,
      grantType,
      signingInput: input(
        { alg: 'RS256', kid: 'k1', typ: 'at+jwt' },
        {
          iss: ISSUER,
          sub: 'user-1',
          aud: BUILT_IN,
          iat: issuedAt,
          exp: issuedAt + 60,
          jti: 'jti-1',
          client_id: 'cli',
          scope: 'session:exchange',
          ...claims,
        },
      ),
    };
  }

  beforeEach(() => {
    vi.mocked(getSystemConfig).mockResolvedValue({
      oidc_issuer: ISSUER,
      session_idle_ttl: '8h',
    } as never);
    vi.mocked(getActiveOidcSigningKey).mockReturnValue(privateKey);
    vi.mocked(findActiveOidcClient).mockResolvedValue({
      id: 'cli',
      grantTypes: ['authorization_code', DEVICE, 'refresh_token', 'client_credentials'],
      firstParty: true,
      deviceFlowEnabled: true,
    } as never);
    vi.mocked(getOidcClientResourceScopes).mockResolvedValue(
      new Map([
        [BUILT_IN, new Set(['session:exchange', 'notices:send'])],
        [API, new Set(['session:exchange'])],
      ]),
    );
    vi.mocked(resolveCurrentSession).mockResolvedValue(passkeySession as never);
    vi.mocked(hasOidcGrantForSession).mockResolvedValue(true);
    vi.mocked(recordSessionExchangeToken).mockResolvedValue(true);
  });

  it('is signed and recorded', async () => {
    const outcome = await signForOidcEdge(exchangeRequest({}, DEVICE));

    expect(outcome).toMatchObject({ ok: true });
    expect(recordSessionExchangeToken).toHaveBeenCalledWith(
      'jti-1',
      SESSION,
      { clientId: 'cli', accountId: 'user-1', grantType: DEVICE },
      expect.any(Date),
    );
  });

  it('is refused when the jti was seen before', async () => {
    vi.mocked(recordSessionExchangeToken).mockResolvedValue(false);

    expect(await signForOidcEdge(exchangeRequest())).toMatchObject({
      ok: false,
      code: 'malformed_signing_input',
    });
  });

  it.each([
    ['another scope', { scope: 'session:exchange notices:send' }, 'grant_not_allowed'],
    ['another resource', { aud: API }, 'audience_mismatch'],
    ['no jti', { jti: undefined }, 'malformed_signing_input'],
    ['an empty jti', { jti: '' }, 'malformed_signing_input'],
    ['no iat', { iat: undefined }, 'malformed_signing_input'],
    ['a long lifetime', { exp: now() + 600 }, 'malformed_signing_input'],
    ['a future iat', { iat: now() + 1000, exp: now() + 1100 }, 'malformed_signing_input'],
  ] as [string, Record<string, unknown>, string][])(
    'is refused with %s',
    async (_name, claims, code) => {
      expect(await signForOidcEdge(exchangeRequest(claims))).toMatchObject({ ok: false, code });
      expect(recordSessionExchangeToken).not.toHaveBeenCalled();
    },
  );

  it('is refused on a refresh grant', async () => {
    expect(await signForOidcEdge(exchangeRequest({}, 'refresh_token'))).toMatchObject({
      ok: false,
      code: 'grant_not_allowed',
    });
  });

  it('is refused on a client credentials token', async () => {
    const issuedAt = now();
    const outcome = await signForOidcEdge({
      kind: 'client_credentials',
      kid: 'k1',
      clientId: 'cli',
      signingInput: input(
        { alg: 'RS256', kid: 'k1', typ: 'at+jwt' },
        {
          iss: ISSUER,
          sub: 'cli',
          aud: BUILT_IN,
          iat: issuedAt,
          exp: issuedAt + 60,
          jti: 'jti-1',
          client_id: 'cli',
          scope: 'session:exchange',
        },
      ),
    } as never);

    expect(outcome).toMatchObject({ ok: false, code: 'grant_not_allowed' });
  });
});
