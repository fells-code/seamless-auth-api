import { generateKeyPairSync, randomUUID } from 'crypto';
import { SignJWT } from 'jose';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const { provider } = vi.hoisted(() => ({ provider: { jwk: {} as Record<string, unknown> } }));

vi.mock('../../../src/models/oidcPayloads', () => ({
  OidcPayload: {
    findOne: vi.fn(),
    update: vi.fn(),
    sequelize: { transaction: (fn: (transaction: unknown) => unknown) => fn({}) },
  },
}));

vi.mock('../../../src/services/oidcAuthContext', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/services/oidcAuthContext')>()),
  resolveCurrentSession: vi.fn(),
}));

vi.mock('../../../src/services/oidcClientRegistry', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/services/oidcClientRegistry')>()),
  findActiveOidcClient: vi.fn(),
}));

vi.mock('../../../src/services/oidcProviderKeys', () => ({
  getOidcPublicJwks: vi.fn(() => ({ activeKid: 'k1', keys: [provider.jwk] })),
}));

vi.mock('../../../src/services/authEventService', () => ({
  AuthEventService: { log: vi.fn() },
}));

vi.mock('../../../src/lib/token', () => ({
  generateRefreshToken: vi.fn(() => 'refresh-token'),
  createRefreshTokenLookup: vi.fn(() => 'lookup'),
  signAccessToken: vi.fn(async () => 'access-token'),
}));

import { getSystemConfig } from '../../../src/config/getSystemConfig';
import { OidcPayload } from '../../../src/models/oidcPayloads';
import { Session } from '../../../src/models/sessions';
import { User } from '../../../src/models/users';
import { AuthEventService } from '../../../src/services/authEventService';
import { resolveCurrentSession } from '../../../src/services/oidcAuthContext';
import { findActiveOidcClient } from '../../../src/services/oidcClientRegistry';
import { getOidcPublicJwks } from '../../../src/services/oidcProviderKeys';
import { exchangeSubjectToken } from '../../../src/services/sessionExchangeService';
import { revokeSessionChain } from '../../../src/services/sessionService';

const ISSUER = 'https://login.example.com';
const RESOURCE = `${ISSUER}/seamless`;
const USER = '11111111-1111-4111-8111-111111111111';
const PARENT = '22222222-2222-4222-8222-222222222222';
const CHILD = '33333333-3333-4333-8333-333333333333';
const CLIENT = 'cli';
const DEVICE = 'urn:ietf:params:oauth:grant-type:device_code';

const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
provider.jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'k1', alg: 'RS256' };

const req = { ip: '127.0.0.1', get: () => 'test-agent' } as never;

function sign(claims: Record<string, unknown> = {}, typ = 'at+jwt') {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({
    iss: ISSUER,
    sub: USER,
    aud: RESOURCE,
    iat: now,
    exp: now + 60,
    jti: 'jti-1',
    client_id: CLIENT,
    scope: 'session:exchange',
    ...claims,
  })
    .setProtectedHeader({ alg: 'RS256', kid: 'k1', typ })
    .sign(privateKey);
}

function record(overrides: Record<string, unknown> = {}) {
  return {
    id: 'jti-1',
    sessionId: PARENT,
    consumedAt: null,
    expiresAt: new Date(Date.now() + 60_000),
    payload: { clientId: CLIENT, accountId: USER, grantType: 'authorization_code' },
    ...overrides,
  };
}

function client(overrides: Record<string, unknown> = {}) {
  return {
    id: CLIENT,
    firstParty: true,
    clientType: 'public',
    tokenEndpointAuthMethod: 'none',
    redirectUris: ['http://127.0.0.1/callback'],
    sessionExchangeEnabled: true,
    ...overrides,
  };
}

const stepUpVerifiedAt = new Date();
const authTime = new Date('2026-11-04T12:00:00.000Z');

function parent(overrides: Record<string, unknown> = {}) {
  return {
    id: PARENT,
    userId: USER,
    infraId: 'infra',
    organizationId: 'org',
    recovery: false,
    parentSessionId: null,
    authMethods: [{ method: 'passkey' }],
    authTime,
    stepUpVerifiedAt,
    stepUpMethod: 'webauthn',
    expiresAt: new Date(Date.now() + 60_000),
    ...overrides,
  };
}

function created() {
  return vi.mocked(Session.create).mock.calls[0][0] as unknown as Record<string, unknown>;
}

beforeEach(() => {
  vi.mocked(getSystemConfig).mockResolvedValue({
    oidc_issuer: ISSUER,
    access_token_ttl: '15m',
    refresh_token_ttl: '7d',
    session_idle_ttl: '8h',
  } as never);
  vi.mocked(getOidcPublicJwks).mockImplementation(
    () => ({ activeKid: 'k1', keys: [provider.jwk] }) as never,
  );
  vi.mocked(OidcPayload.findOne).mockResolvedValue(record() as never);
  vi.mocked(OidcPayload.update).mockResolvedValue([1] as never);
  vi.mocked(findActiveOidcClient).mockResolvedValue(client() as never);
  vi.mocked(resolveCurrentSession).mockResolvedValue(parent() as never);
  vi.mocked(User.findOne).mockResolvedValue({
    id: USER,
    email: 'a@example.com',
    phone: null,
    roles: ['user'],
  } as never);
  vi.mocked(Session.create).mockResolvedValue({ id: CHILD, parentSessionId: PARENT } as never);
});

describe('exchangeSubjectToken', () => {
  it('issues a child capped at the parent, carrying its assurance', async () => {
    const outcome = await exchangeSubjectToken(await sign(), req);

    expect(outcome).toMatchObject({
      ok: true,
      response: {
        token: 'access-token',
        refreshToken: 'refresh-token',
        sessionId: CHILD,
        sub: USER,
        issued_token_type: 'urn:ietf:params:oauth:token-type:refresh_token',
      },
    });
    const row = created();
    expect(row).toMatchObject({
      parentSessionId: PARENT,
      exchangeClientId: CLIENT,
      exchangeGrantType: 'authorization_code',
      organizationId: 'org',
      authTime,
      stepUpVerifiedAt,
      stepUpMethod: 'webauthn',
    });
    expect((row.expiresAt as Date).getTime()).toBeLessThanOrEqual(Date.now() + 60_000);
    expect(vi.mocked(AuthEventService.log).mock.calls[0][0]).toMatchObject({
      type: 'session_exchanged',
      sessionId: CHILD,
    });
  });

  it('falls back to the chain start for a parent with no recorded auth time', async () => {
    const chainStartedAt = new Date('2026-11-01T00:00:00.000Z');
    vi.mocked(resolveCurrentSession).mockResolvedValue(
      parent({ authTime: null, chainStartedAt }) as never,
    );

    await exchangeSubjectToken(await sign(), req);

    expect(created().authTime).toEqual(chainStartedAt);
  });

  it('copies no assurance for a device grant', async () => {
    vi.mocked(OidcPayload.findOne).mockResolvedValue(
      record({ payload: { clientId: CLIENT, accountId: USER, grantType: DEVICE } }) as never,
    );

    await exchangeSubjectToken(await sign(), req);

    expect(created()).toMatchObject({
      exchangeGrantType: DEVICE,
      authMethods: [],
      authTime: null,
      stepUpVerifiedAt: null,
      stepUpMethod: null,
    });
  });

  it.each([
    ['another audience', { aud: 'https://api.example.com' }],
    ['an audience list', { aud: [RESOURCE, 'https://api.example.com'] }],
    ['an extra scope', { scope: 'session:exchange notices:send' }],
    ['a client as subject', { sub: CLIENT }],
    ['no client_id', { client_id: undefined }],
    ['a numeric client_id', { client_id: 7 }],
    ['no jti', { jti: undefined }],
  ])('refuses a token with %s', async (_name, claims) => {
    expect(await exchangeSubjectToken(await sign(claims), req)).toEqual({
      ok: false,
      replayed: false,
    });
    expect(OidcPayload.update).not.toHaveBeenCalled();
  });

  it('refuses a token that is not at+jwt', async () => {
    expect(await exchangeSubjectToken(await sign({}, 'JWT'), req)).toMatchObject({ ok: false });
  });

  it('refuses when no provider is configured', async () => {
    vi.mocked(getSystemConfig).mockResolvedValue({} as never);

    expect(await exchangeSubjectToken(await sign(), req)).toMatchObject({ ok: false });
  });

  it('refuses when provider keys are unusable', async () => {
    vi.mocked(getOidcPublicJwks).mockImplementation(() => {
      throw new Error('no keys');
    });

    expect(await exchangeSubjectToken(await sign(), req)).toMatchObject({ ok: false });
  });

  it.each([
    ['no record', () => null],
    ['another user', () => record({ payload: { clientId: CLIENT, accountId: randomUUID() } })],
    ['another client', () => record({ payload: { clientId: 'x', accountId: USER } })],
    ['an expired record', () => record({ expiresAt: new Date(Date.now() - 1) })],
    [
      'a grant that cannot exchange',
      () => record({ payload: { clientId: CLIENT, accountId: USER, grantType: 'refresh_token' } }),
    ],
  ])('refuses %s', async (_name, found) => {
    vi.mocked(OidcPayload.findOne).mockResolvedValue(found() as never);

    expect(await exchangeSubjectToken(await sign(), req)).toEqual({ ok: false, replayed: false });
  });

  it.each([
    ['disabled', null],
    ['with the flag off', client({ sessionExchangeEnabled: false })],
    ['third-party', client({ firstParty: false })],
  ])('refuses a client that is %s', async (_name, found) => {
    vi.mocked(findActiveOidcClient).mockResolvedValue(found as never);

    expect(await exchangeSubjectToken(await sign(), req)).toEqual({ ok: false, replayed: false });
  });

  it.each([
    ['gone', null],
    ['another user', parent({ userId: randomUUID() })],
    ['a recovery session', parent({ recovery: true })],
    ['itself a child', parent({ parentSessionId: randomUUID() })],
  ])('refuses a parent that is %s', async (_name, found) => {
    vi.mocked(resolveCurrentSession).mockResolvedValue(found as never);

    expect(await exchangeSubjectToken(await sign(), req)).toEqual({ ok: false, replayed: false });
  });

  it('refuses a record with no session', async () => {
    vi.mocked(OidcPayload.findOne).mockResolvedValue(record({ sessionId: null }) as never);

    expect(await exchangeSubjectToken(await sign(), req)).toEqual({ ok: false, replayed: false });
  });

  it('refuses a revoked user', async () => {
    vi.mocked(User.findOne).mockResolvedValue(null as never);

    expect(await exchangeSubjectToken(await sign(), req)).toEqual({ ok: false, replayed: false });
  });

  describe('a replay', () => {
    const consumed = () =>
      record({
        consumedAt: new Date(),
        payload: { clientId: CLIENT, accountId: USER, childSessionId: CHILD },
      });

    it('revokes what the first use created', async () => {
      vi.mocked(OidcPayload.findOne).mockResolvedValue(consumed() as never);
      const child = { id: CHILD, parentSessionId: PARENT };
      vi.mocked(Session.findByPk).mockResolvedValue(child as never);

      expect(await exchangeSubjectToken(await sign(), req)).toEqual({ ok: false, replayed: true });

      expect(revokeSessionChain).toHaveBeenCalledWith(child, 'session_exchange_replayed');
      expect(vi.mocked(AuthEventService.log).mock.calls[0][0]).toMatchObject({
        type: 'session_exchange_replayed',
        sessionId: CHILD,
        metadata: { clientId: CLIENT, parentSessionId: PARENT },
      });
    });

    it('is still refused when the child is gone', async () => {
      vi.mocked(OidcPayload.findOne).mockResolvedValue(
        record({
          consumedAt: new Date(),
          payload: { clientId: CLIENT, accountId: USER },
        }) as never,
      );

      expect(await exchangeSubjectToken(await sign(), req)).toEqual({ ok: false, replayed: true });
      expect(revokeSessionChain).not.toHaveBeenCalled();
    });

    it('is caught when another presentation wins the consume', async () => {
      vi.mocked(OidcPayload.update).mockResolvedValue([0] as never);
      vi.mocked(OidcPayload.findOne)
        .mockResolvedValueOnce(record() as never)
        .mockResolvedValueOnce(consumed() as never);
      vi.mocked(Session.findByPk).mockResolvedValue({ id: CHILD } as never);

      expect(await exchangeSubjectToken(await sign(), req)).toEqual({ ok: false, replayed: true });
      expect(Session.create).not.toHaveBeenCalled();
    });
  });

  it('refuses without a replay when the record expires during the consume', async () => {
    vi.mocked(OidcPayload.update).mockResolvedValue([0] as never);
    vi.mocked(OidcPayload.findOne)
      .mockResolvedValueOnce(record() as never)
      .mockResolvedValueOnce(record() as never);

    expect(await exchangeSubjectToken(await sign(), req)).toEqual({ ok: false, replayed: false });
  });

  it('revokes the child when the client is switched off during the exchange', async () => {
    vi.mocked(findActiveOidcClient)
      .mockResolvedValueOnce(client() as never)
      .mockResolvedValueOnce(client({ sessionExchangeEnabled: false }) as never);

    expect(await exchangeSubjectToken(await sign(), req)).toEqual({ ok: false, replayed: false });

    expect(revokeSessionChain).toHaveBeenCalledWith(
      expect.objectContaining({ id: CHILD }),
      'session_exchange_disabled',
    );
    expect(AuthEventService.log).not.toHaveBeenCalled();
  });
});
