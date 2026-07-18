import { beforeEach, describe, expect, it, vi } from 'vitest';
import { buildSession } from '../../factories/sessionFactory';

vi.unmock('../../../src/services/sessionService');
vi.mock('../../../src/models/sessions', () => ({
  Session: {
    findByPk: vi.fn(),
    findOne: vi.fn(),
    findAll: vi.fn(),
  },
}));

vi.mock('../../../src/models/users', () => ({
  User: {
    findOne: vi.fn(),
  },
}));

vi.mock('../../../src/utils/secretsStore', () => ({
  getSecret: vi.fn(),
}));

vi.mock('../../../src/utils/signingKeyStore', () => ({
  getPublicKeyByKid: vi.fn(),
}));

vi.mock('../../../src/lib/token', () => ({
  createRefreshTokenLookup: vi.fn(),
}));

vi.mock('jose', () => ({
  jwtVerify: vi.fn(),
  importSPKI: vi.fn(),
}));

vi.mock('bcrypt-ts', () => ({
  compareSync: vi.fn(),
}));

vi.mock('jsonwebtoken', () => ({
  default: {
    verify: vi.fn(),
  },
}));

describe('sessionService', () => {
  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();
  });

  it('returns payload when valid', async () => {
    const jose = await import('jose');
    const { getPublicKeyByKid } = await import('../../../src/utils/signingKeyStore');

    (getPublicKeyByKid as any).mockResolvedValue('pem');

    (jose.jwtVerify as any).mockResolvedValue({
      payload: {
        typ: 'access',
        sub: 'user',
        sid: 'session',
      },
    });

    const { verifyJwtWithKid } = await import('../../../src/services/sessionService');

    const result = await verifyJwtWithKid('token', 'access');

    expect(result).toBeDefined();
  });

  it('returns null on mismatch type', async () => {
    const jose = await import('jose');

    (jose.jwtVerify as any).mockResolvedValue({
      payload: { typ: 'wrong' },
    });

    const { verifyJwtWithKid } = await import('../../../src/services/sessionService');

    const result = await verifyJwtWithKid('token', 'access');

    expect(result).toBeNull();
  });

  it('returns null on error', async () => {
    const jose = await import('jose');

    (jose.jwtVerify as any).mockRejectedValue(new Error('fail'));

    const { verifyJwtWithKid } = await import('../../../src/services/sessionService');

    const result = await verifyJwtWithKid('token');

    expect(result).toBeNull();
  });

  it('returns parsed access token', async () => {
    const jose = await import('jose');
    const { getPublicKeyByKid } = await import('../../../src/utils/signingKeyStore');

    (getPublicKeyByKid as any).mockResolvedValue('pem');
    (jose.jwtVerify as any).mockResolvedValue({
      payload: {
        typ: 'access',
        sub: 'user',
        sid: 'session',
        roles: ['admin'],
      },
    });

    const { validateAccessToken } = await import('../../../src/services/sessionService');

    const result = await validateAccessToken('token');

    expect(result).toEqual({
      userId: 'user',
      sessionId: 'session',
      roles: ['admin'],
      organizationId: null,
    });
  });

  it('returns null if payload invalid', async () => {
    const jose = await import('jose');
    const { getPublicKeyByKid } = await import('../../../src/utils/signingKeyStore');
    const { validateAccessToken } = await import('../../../src/services/sessionService');

    (getPublicKeyByKid as any).mockResolvedValue('pem');
    (jose.jwtVerify as any).mockResolvedValue({
      payload: { typ: 'access', sub: 'user' },
    });

    const result = await validateAccessToken('token');

    expect(result).toBeNull();
  });

  it('returns null if session missing', async () => {
    const { Session } = await import('../../../src/models/sessions');

    (Session.findByPk as any).mockResolvedValue(null);

    const { validateSessionRecord } = await import('../../../src/services/sessionService');

    const result = await validateSessionRecord('id');

    expect(result).toBeNull();
  });

  it('returns null if revoked', async () => {
    const { Session } = await import('../../../src/models/sessions');

    (Session.findByPk as any).mockResolvedValue(buildSession({ revokedAt: new Date() }));

    const { validateSessionRecord } = await import('../../../src/services/sessionService');

    const result = await validateSessionRecord('id');

    expect(result).toBeNull();
  });

  it('returns null when the session lifetime has expired', async () => {
    const { Session } = await import('../../../src/models/sessions');

    (Session.findByPk as any).mockResolvedValue(
      buildSession({
        expiresAt: new Date(Date.now() - 1000),
        idleExpiresAt: new Date(Date.now() + 1000),
      }),
    );

    const { validateSessionRecord } = await import('../../../src/services/sessionService');

    expect(await validateSessionRecord('id')).toBeNull();
  });

  it('returns null when the session idle window has expired', async () => {
    const { Session } = await import('../../../src/models/sessions');

    (Session.findByPk as any).mockResolvedValue(
      buildSession({
        expiresAt: new Date(Date.now() + 1000),
        idleExpiresAt: new Date(Date.now() - 1000),
      }),
    );

    const { validateSessionRecord } = await import('../../../src/services/sessionService');

    expect(await validateSessionRecord('id')).toBeNull();
  });

  it('returns session if valid', async () => {
    const { Session } = await import('../../../src/models/sessions');

    const session = buildSession();

    (Session.findByPk as any).mockResolvedValue(session);

    const { validateSessionRecord } = await import('../../../src/services/sessionService');

    const result = await validateSessionRecord('id');

    expect(result).toBe(session);
  });

  it('finds a refresh session by its indexed lookup fingerprint', async () => {
    const { Session } = await import('../../../src/models/sessions');
    const { createRefreshTokenLookup } = await import('../../../src/lib/token');

    const session = buildSession();

    (createRefreshTokenLookup as any).mockReturnValue('lookup');
    (Session.findOne as any).mockResolvedValue(session);

    const { findRefreshSessionByToken } = await import('../../../src/services/sessionService');

    const result = await findRefreshSessionByToken('refresh-token');

    expect(Session.findOne).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({
          refreshTokenLookup: 'lookup',
        }),
      }),
    );
    expect(result).toBe(session);
  });

  it('returns null when no session matches the lookup fingerprint', async () => {
    const { Session } = await import('../../../src/models/sessions');
    const { createRefreshTokenLookup } = await import('../../../src/lib/token');

    (createRefreshTokenLookup as any).mockReturnValue('lookup');
    (Session.findOne as any).mockResolvedValue(null);

    const { findRefreshSessionByToken } = await import('../../../src/services/sessionService');

    const result = await findRefreshSessionByToken('refresh-token');

    expect(result).toBeNull();
  });

  it('revokes replaced sessions during validateSessionRecord', async () => {
    const { Session } = await import('../../../src/models/sessions');
    const mod = await import('../../../src/services/sessionService');

    const session = buildSession({ replacedBySessionId: 'next-session' });
    (Session.findByPk as any).mockResolvedValue(session);

    const result = await mod.validateSessionRecord('id');

    expect(session.save).toHaveBeenCalled();
    expect(result).toBeNull();
  });

  it('revokes chain', async () => {
    const { Session } = await import('../../../src/models/sessions');

    const session = buildSession({
      replacedBySessionId: 'next',
    });

    (Session.findByPk as any).mockResolvedValue(null);

    const { revokeSessionChain } = await import('../../../src/services/sessionService');

    await revokeSessionChain(session as any);

    expect(session.save).toHaveBeenCalled();
  });

  it('stops revoking the chain when a session has no replacement', async () => {
    const { Session } = await import('../../../src/models/sessions');

    const session = buildSession({ replacedBySessionId: null });

    const { revokeSessionChain } = await import('../../../src/services/sessionService');

    await revokeSessionChain(session as any);

    expect(session.save).toHaveBeenCalled();
    expect(Session.findByPk).not.toHaveBeenCalled();
  });

  it('rejects access tokens whose subject or session id are not strings', async () => {
    const jose = await import('jose');
    const { getPublicKeyByKid } = await import('../../../src/utils/signingKeyStore');

    (getPublicKeyByKid as any).mockResolvedValue('pem');
    (jose.jwtVerify as any).mockResolvedValue({
      payload: { typ: 'access', sub: 123, sid: 'session' },
    });

    const { validateAccessToken } = await import('../../../src/services/sessionService');

    expect(await validateAccessToken('token')).toBeNull();
  });

  it('revokes session immediately', async () => {
    const session = buildSession();

    const { hardRevokeSession } = await import('../../../src/services/sessionService');

    await hardRevokeSession(session as any);

    expect(session.save).toHaveBeenCalled();
  });

  it('returns user if found', async () => {
    const { User } = await import('../../../src/models/users');

    (User.findOne as any).mockResolvedValue({ id: 'user' });

    const { getUserFromSession } = await import('../../../src/services/sessionService');

    const result = await getUserFromSession({ userId: 'user' } as any);

    expect(result).toBeTruthy();
  });

  it('returns null if not found', async () => {
    const { User } = await import('../../../src/models/users');

    (User.findOne as any).mockResolvedValue(null);

    const { getUserFromSession } = await import('../../../src/services/sessionService');

    const result = await getUserFromSession({ userId: 'user' } as any);

    expect(result).toBeNull();
  });

  it('returns user when access bearer token and session are valid', async () => {
    const jose = await import('jose');
    const { getPublicKeyByKid } = await import('../../../src/utils/signingKeyStore');
    const { Session } = await import('../../../src/models/sessions');
    const { User } = await import('../../../src/models/users');

    (getPublicKeyByKid as any).mockResolvedValue('pem');
    (jose.jwtVerify as any).mockResolvedValue({
      payload: {
        typ: 'access',
        sub: 'user',
        sid: 'session-1',
        org_id: 'org-1',
      },
    });

    (Session.findByPk as any).mockResolvedValue(buildSession({ id: 'session-1', userId: 'user' }));
    const user = { id: 'user' };
    (User.findOne as any).mockResolvedValue(user);

    const { validateBearerToken } = await import('../../../src/services/sessionService');

    const result = await validateBearerToken('token');

    expect(result).toEqual({
      user,
      sessionId: 'session-1',
      organizationId: 'org-1',
    });
  });

  it('returns null when access bearer token subject does not match the session owner', async () => {
    const jose = await import('jose');
    const { getPublicKeyByKid } = await import('../../../src/utils/signingKeyStore');
    const { Session } = await import('../../../src/models/sessions');

    (getPublicKeyByKid as any).mockResolvedValue('pem');
    (jose.jwtVerify as any).mockResolvedValue({
      payload: {
        typ: 'access',
        sub: 'user',
        sid: 'session-1',
      },
    });

    (Session.findByPk as any).mockResolvedValue(buildSession({ id: 'session-1', userId: 'other' }));

    const { validateBearerToken } = await import('../../../src/services/sessionService');

    const result = await validateBearerToken('token');

    expect(result).toBeNull();
  });

  it('returns user when ephemeral bearer token is valid', async () => {
    const jose = await import('jose');
    const { getPublicKeyByKid } = await import('../../../src/utils/signingKeyStore');
    const { User } = await import('../../../src/models/users');

    (getPublicKeyByKid as any).mockResolvedValue('pem');
    (jose.jwtVerify as any).mockResolvedValue({
      payload: {
        typ: 'ephemeral',
        sub: 'user',
      },
    });

    const user = { id: 'user' };
    (User.findOne as any).mockResolvedValue(user);

    const { validateBearerToken } = await import('../../../src/services/sessionService');

    const result = await validateBearerToken('token', 'ephemeral');

    expect(result).toEqual({ user });
  });

  it('returns null if jwt verification fails', async () => {
    const jose = await import('jose');

    (jose.jwtVerify as any).mockRejectedValue(new Error('fail'));

    const { validateBearerToken } = await import('../../../src/services/sessionService');

    const result = await validateBearerToken('token');

    expect(result).toBeNull();
  });

  it('resolves the signing key from the JWT header kid', async () => {
    const jose = await import('jose');
    const { getPublicKeyByKid } = await import('../../../src/utils/signingKeyStore');

    (getPublicKeyByKid as any).mockResolvedValue('pem');
    (jose.importSPKI as any).mockResolvedValue('key');
    (jose.jwtVerify as any).mockImplementation(async (_token: string, getKey: any) => {
      await getKey({ kid: 'kid-1' });
      return { payload: { typ: 'access', sub: 'user', sid: 'session' } };
    });

    const { verifyJwtWithKid } = await import('../../../src/services/sessionService');

    const result = await verifyJwtWithKid('token', 'access');

    expect(getPublicKeyByKid).toHaveBeenCalledWith('kid-1');
    expect(jose.importSPKI).toHaveBeenCalledWith('pem', 'RS256');
    expect(result).toBeDefined();
  });

  it('returns null when the JWT header is missing a kid', async () => {
    const jose = await import('jose');

    (jose.jwtVerify as any).mockImplementation(async (_token: string, getKey: any) => {
      await getKey({});
      return { payload: { typ: 'access', sub: 'user', sid: 'session' } };
    });

    const { verifyJwtWithKid } = await import('../../../src/services/sessionService');

    const result = await verifyJwtWithKid('token', 'access');

    expect(result).toBeNull();
  });

  it('returns null when no public key is registered for the kid', async () => {
    const jose = await import('jose');
    const { getPublicKeyByKid } = await import('../../../src/utils/signingKeyStore');

    (getPublicKeyByKid as any).mockResolvedValue(null);
    (jose.jwtVerify as any).mockImplementation(async (_token: string, getKey: any) => {
      await getKey({ kid: 'kid-1' });
      return { payload: { typ: 'access', sub: 'user', sid: 'session' } };
    });

    const { verifyJwtWithKid } = await import('../../../src/services/sessionService');

    const result = await verifyJwtWithKid('token', 'access');

    expect(result).toBeNull();
  });

  it('returns null when an access token is missing its subject', async () => {
    const jose = await import('jose');

    (jose.jwtVerify as any).mockResolvedValue({
      payload: { typ: 'access', sid: 'session' },
    });

    const { verifyJwtWithKid } = await import('../../../src/services/sessionService');

    const result = await verifyJwtWithKid('token', 'access');

    expect(result).toBeNull();
  });

  it('returns null when an ephemeral token is missing its subject', async () => {
    const jose = await import('jose');

    (jose.jwtVerify as any).mockResolvedValue({
      payload: { typ: 'ephemeral' },
    });

    const { verifyJwtWithKid } = await import('../../../src/services/sessionService');

    const result = await verifyJwtWithKid('token', 'ephemeral');

    expect(result).toBeNull();
  });

  it('returns null when an ephemeral bearer token cannot be verified', async () => {
    const jose = await import('jose');

    (jose.jwtVerify as any).mockRejectedValue(new Error('fail'));

    const { validateBearerToken } = await import('../../../src/services/sessionService');

    const result = await validateBearerToken('token', 'ephemeral');

    expect(result).toBeNull();
  });

  it('returns null when an ephemeral token subject has no matching user', async () => {
    const jose = await import('jose');
    const { getPublicKeyByKid } = await import('../../../src/utils/signingKeyStore');
    const { User } = await import('../../../src/models/users');

    (getPublicKeyByKid as any).mockResolvedValue('pem');
    (jose.jwtVerify as any).mockResolvedValue({
      payload: { typ: 'ephemeral', sub: 'user' },
    });
    (User.findOne as any).mockResolvedValue(null);

    const { validateBearerToken } = await import('../../../src/services/sessionService');

    expect(await validateBearerToken('token', 'ephemeral')).toBeNull();
  });

  it('returns null when the session owner cannot be loaded', async () => {
    const jose = await import('jose');
    const { getPublicKeyByKid } = await import('../../../src/utils/signingKeyStore');
    const { Session } = await import('../../../src/models/sessions');
    const { User } = await import('../../../src/models/users');

    (getPublicKeyByKid as any).mockResolvedValue('pem');
    (jose.jwtVerify as any).mockResolvedValue({
      payload: { typ: 'access', sub: 'user', sid: 'session-1' },
    });
    (Session.findByPk as any).mockResolvedValue(buildSession({ id: 'session-1', userId: 'user' }));
    (User.findOne as any).mockResolvedValue(null);

    const { validateBearerToken } = await import('../../../src/services/sessionService');

    expect(await validateBearerToken('token')).toBeNull();
  });

  it('returns null when the access token session record is missing', async () => {
    const jose = await import('jose');
    const { getPublicKeyByKid } = await import('../../../src/utils/signingKeyStore');
    const { Session } = await import('../../../src/models/sessions');

    (getPublicKeyByKid as any).mockResolvedValue('pem');
    (jose.jwtVerify as any).mockResolvedValue({
      payload: { typ: 'access', sub: 'user', sid: 'session-1' },
    });
    (Session.findByPk as any).mockResolvedValue(null);

    const { validateBearerToken } = await import('../../../src/services/sessionService');

    const result = await validateBearerToken('token');

    expect(result).toBeNull();
  });
});
