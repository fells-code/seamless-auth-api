import { beforeEach, describe, expect, it, vi } from 'vitest';
import { buildSession } from '../../factories/sessionFactory';

vi.unmock('../../../src/services/sessionService');
vi.mock('../../../src/models/sessions', () => ({
  Session: {
    findByPk: vi.fn(),
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

vi.mock('jose', () => ({
  jwtVerify: vi.fn(),
  importSPKI: vi.fn(),
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

  it.skip('returns parsed access token', async () => {
    const { verifyJwtWithKid } = await import('../../../src/services/sessionService');

    vi.spyOn(
      await import('../../../src/services/sessionService'),
      'verifyJwtWithKid',
    ).mockResolvedValue({
      sub: 'user',
      sid: 'session',
      roles: ['admin'],
    } as any);

    const { validateAccessToken } = await import('../../../src/services/sessionService');

    const result = await validateAccessToken('token');

    expect(result).toEqual({
      userId: 'user',
      sessionId: 'session',
      roles: ['admin'],
    });
  });

  it('returns null if payload invalid', async () => {
    const mod = await import('../../../src/services/sessionService');

    vi.spyOn(mod, 'verifyJwtWithKid').mockResolvedValue(null);

    const result = await mod.validateAccessToken('token');

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

  it('returns session if valid', async () => {
    const { Session } = await import('../../../src/models/sessions');

    const session = buildSession();

    (Session.findByPk as any).mockResolvedValue(session);

    const { validateSessionRecord } = await import('../../../src/services/sessionService');

    const result = await validateSessionRecord('id');

    expect(result).toBe(session);
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

  it('returns user when valid', async () => {
    const { getSecret } = await import('../../../src/utils/secretsStore');
    const jwt = await import('jsonwebtoken');
    const { User } = await import('../../../src/models/users');

    (getSecret as any).mockResolvedValue('secret');

    (jwt.default.verify as any).mockReturnValue({
      sub: 'user',
    });

    (User.findOne as any).mockResolvedValue({ id: 'user' });

    const { validateBearerToken } = await import('../../../src/services/sessionService');

    const result = await validateBearerToken('token');

    expect(result).toBeTruthy();
  });

  it('returns null if jwt fails', async () => {
    const { getSecret } = await import('../../../src/utils/secretsStore');
    const jwt = await import('jsonwebtoken');

    (getSecret as any).mockResolvedValue('secret');

    (jwt.default.verify as any).mockImplementation(() => {
      throw new Error('fail');
    });

    const { validateBearerToken } = await import('../../../src/services/sessionService');

    const result = await validateBearerToken('token');

    expect(result).toBeNull();
  });
});
