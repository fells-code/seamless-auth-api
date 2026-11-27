import { beforeEach, describe, expect, it, vi } from 'vitest';
import { buildSession } from '../../factories/sessionFactory';

vi.unmock('../../../src/services/sessionService');
vi.mock('../../../src/models/sessions', () => ({
  Session: {
    findByPk: vi.fn(),
    findOne: vi.fn(),
    findAll: vi.fn(),
    update: vi.fn(),
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

vi.mock('../../../src/lib/refreshReplayToken', () => ({
  MAX_REFRESH_REPLAYS: 3,
  openReplayToken: vi.fn(),
  refreshReplayWindowMs: vi.fn(() => 5_000),
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
  compare: vi.fn(async () => true),
}));

vi.mock('jsonwebtoken', () => ({
  default: {
    verify: vi.fn(),
  },
}));

vi.mock('../../../src/services/oidcAuthContext', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/services/oidcAuthContext')>()),
  resolveCurrentSession: vi.fn(),
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

    const result = await verifyJwtWithKid('token', 'either');

    expect(result).toBeNull();
  });

  it('checks the audience as well as the issuer', async () => {
    const jose = await import('jose');

    (jose.jwtVerify as any).mockResolvedValue({ payload: { typ: 'access', sub: 'u', sid: 's' } });

    const { verifyJwtWithKid } = await import('../../../src/services/sessionService');

    await verifyJwtWithKid('token', 'access');

    expect(jose.jwtVerify).toHaveBeenCalledWith(
      'token',
      expect.any(Function),
      expect.objectContaining({ issuer: process.env.ISSUER, audience: process.env.ISSUER }),
    );
  });

  it('rejects a token of the other kind', async () => {
    const jose = await import('jose');

    (jose.jwtVerify as any).mockResolvedValue({ payload: { typ: 'ephemeral', sub: 'u' } });

    const { verifyJwtWithKid } = await import('../../../src/services/sessionService');

    await expect(verifyJwtWithKid('token', 'access')).resolves.toBeNull();
  });

  // Misuse detection asks for either kind, but a token whose typ is neither, such as
  // one a future OpenID Provider signs, is still not one of ours.
  it('rejects an unrecognised typ even when either kind is accepted', async () => {
    const jose = await import('jose');

    (jose.jwtVerify as any).mockResolvedValue({ payload: { typ: 'id_token', sub: 'u' } });

    const { verifyJwtWithKid } = await import('../../../src/services/sessionService');

    await expect(verifyJwtWithKid('token', 'either')).resolves.toBeNull();
  });

  it('accepts either kind for misuse detection', async () => {
    const jose = await import('jose');

    (jose.jwtVerify as any).mockResolvedValue({ payload: { typ: 'ephemeral', sub: 'u' } });

    const { verifyJwtWithKid } = await import('../../../src/services/sessionService');

    await expect(verifyJwtWithKid('token', 'either')).resolves.toEqual(
      expect.objectContaining({ typ: 'ephemeral' }),
    );
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
    const { User } = await import('../../../src/models/users');

    const session = buildSession({ userId: 'user-1' });

    (Session.findByPk as any).mockResolvedValue(session);
    (User.findOne as any).mockResolvedValue({ id: 'user-1', sessionsRevokedBefore: null });

    const { validateSessionRecord } = await import('../../../src/services/sessionService');

    const result = await validateSessionRecord('id');

    expect(result).toBe(session);
    expect(User.findOne).toHaveBeenCalledWith({
      where: { id: 'user-1' },
      attributes: ['id', 'sessionsRevokedBefore'],
    });
  });

  describe('after a revoke-all', () => {
    const revokedAt = new Date('2026-10-22T12:00:00Z');

    async function validate(createdAt: Date | undefined) {
      const { Session } = await import('../../../src/models/sessions');
      const { User } = await import('../../../src/models/users');

      (Session.findByPk as any).mockResolvedValue(buildSession({ userId: 'user-1', createdAt }));
      (User.findOne as any).mockResolvedValue({ id: 'user-1', sessionsRevokedBefore: revokedAt });

      const { validateSessionRecord } = await import('../../../src/services/sessionService');

      return validateSessionRecord('id');
    }

    it('refuses a session created before the cutoff that the revoke missed', async () => {
      expect(await validate(new Date(revokedAt.getTime() - 1))).toBeNull();
    });

    it('refuses a session created at the cutoff', async () => {
      expect(await validate(revokedAt)).toBeNull();
    });

    it('refuses a session with no creation time', async () => {
      expect(await validate(undefined)).toBeNull();
    });

    it('accepts a session started after the cutoff', async () => {
      expect(await validate(new Date(revokedAt.getTime() + 1))).not.toBeNull();
    });
  });

  it('refuses a session whose owner no longer exists', async () => {
    const { Session } = await import('../../../src/models/sessions');
    const { User } = await import('../../../src/models/users');

    (Session.findByPk as any).mockResolvedValue(buildSession({ userId: 'user-1' }));
    (User.findOne as any).mockResolvedValue(null);

    const { validateSessionRecord } = await import('../../../src/services/sessionService');

    expect(await validateSessionRecord('id')).toBeNull();
  });

  // The keyed fingerprint is what authenticates the token, so a row whose stored value
  // does not match the presented one is refused even though the query returned it.
  it('refuses a session whose stored fingerprint does not match', async () => {
    const { Session } = await import('../../../src/models/sessions');
    const { createRefreshTokenLookup } = await import('../../../src/lib/token');

    (createRefreshTokenLookup as any).mockReturnValue('lookup');
    (Session.findOne as any).mockResolvedValue(buildSession({ refreshTokenLookup: 'other' }));

    const { findRefreshSessionByToken } = await import('../../../src/services/sessionService');

    expect(await findRefreshSessionByToken('refresh-token')).toBeNull();
  });

  it('finds a refresh session by its indexed lookup fingerprint', async () => {
    const { Session } = await import('../../../src/models/sessions');
    const { createRefreshTokenLookup } = await import('../../../src/lib/token');

    const session = buildSession({ refreshTokenLookup: 'lookup' });

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

  // Rotated, revoked and expired rows all come back, so a rotated token is still known
  // as reuse after its own idle window (#593).
  it('looks a refresh token up by its fingerprint alone, whatever state its row is in', async () => {
    const { Session } = await import('../../../src/models/sessions');
    const { createRefreshTokenLookup } = await import('../../../src/lib/token');

    const session = buildSession({
      refreshTokenLookup: 'lookup',
      replacedBySessionId: 'session-2',
      idleExpiresAt: new Date(Date.now() - 1000),
    });
    (createRefreshTokenLookup as any).mockReturnValue('lookup');
    (Session.findOne as any).mockResolvedValue(session);

    const { findRefreshSessionByToken } = await import('../../../src/services/sessionService');

    expect(await findRefreshSessionByToken('refresh-token')).toBe(session);
    expect(Session.findOne).toHaveBeenCalledWith({ where: { refreshTokenLookup: 'lookup' } });
  });

  describe('replayRefreshRotation', () => {
    const now = new Date();
    const successorRow = () =>
      buildSession({
        id: 'session-2',
        userId: 'user-1',
        refreshTokenLookup: 'successor-lookup',
        replacedBySessionId: null,
        expiresAt: new Date(now.getTime() + 3_600_000),
        idleExpiresAt: new Date(now.getTime() + 3_600_000),
      });
    const rotatedRow = (overrides: Record<string, unknown> = {}) =>
      buildSession({
        id: 'session-1',
        userId: 'user-1',
        replacedBySessionId: 'session-2',
        rotatedAt: new Date(now.getTime() - 2_000),
        replayTokenCiphertext: 'sealed',
        ...overrides,
      });

    async function setUp({
      successor = successorRow() as unknown,
      opened = 'successor-token' as string | null,
      claimed = 1,
      windowMs = 5_000,
    } = {}) {
      const { Session } = await import('../../../src/models/sessions');
      const { User } = await import('../../../src/models/users');
      const { createRefreshTokenLookup } = await import('../../../src/lib/token');
      const replayToken = await import('../../../src/lib/refreshReplayToken');

      (replayToken.refreshReplayWindowMs as any).mockReturnValue(windowMs);
      (replayToken.openReplayToken as any).mockReturnValue(opened);
      (createRefreshTokenLookup as any).mockReturnValue('successor-lookup');
      (Session.findByPk as any).mockResolvedValue(successor);
      (Session.update as any).mockResolvedValue([claimed]);
      (User.findOne as any).mockResolvedValue({ id: 'user-1', sessionsRevokedBefore: null });

      const { replayRefreshRotation } = await import('../../../src/services/sessionService');
      return { Session, User, replayToken, replayRefreshRotation };
    }

    it('answers the immediate predecessor with its existing successor', async () => {
      const { Session, replayToken, replayRefreshRotation } = await setUp();
      const session = rotatedRow();

      const replay = await replayRefreshRotation(session as any, 'predecessor-token', now);

      expect(replay?.successor.id).toBe('session-2');
      expect(replay?.refreshToken).toBe('successor-token');
      expect(replayToken.openReplayToken).toHaveBeenCalledWith(
        {
          predecessorToken: 'predecessor-token',
          predecessorId: 'session-1',
          successorId: 'session-2',
        },
        'sealed',
      );
      const [values, { where }] = (Session.update as any).mock.calls[0];
      expect(Object.keys(values)).toEqual(['replayCount']);
      expect(where).toEqual(
        expect.objectContaining({
          id: 'session-1',
          revokedAt: null,
          replacedBySessionId: 'session-2',
        }),
      );
    });

    it('refuses once the window has passed, and discards the sealed token', async () => {
      const { Session, replayRefreshRotation } = await setUp();
      const session = rotatedRow({ rotatedAt: new Date(now.getTime() - 6_000) });

      expect(await replayRefreshRotation(session as any, 'predecessor-token', now)).toBeNull();
      expect(Session.update).toHaveBeenCalledWith(
        { replayTokenCiphertext: null },
        { where: { id: 'session-1' } },
      );
      expect(Session.findByPk).not.toHaveBeenCalled();
    });

    it('refuses everything while the window is disabled', async () => {
      const { replayRefreshRotation } = await setUp({ windowMs: 0 });

      expect(await replayRefreshRotation(rotatedRow() as any, 'predecessor-token', now)).toBeNull();
    });

    it('refuses a row that is revoked, unrotated or carries nothing to replay', async () => {
      const { Session, replayRefreshRotation } = await setUp();

      for (const overrides of [
        { revokedAt: now },
        { replacedBySessionId: null },
        { rotatedAt: null },
        { replayTokenCiphertext: null },
      ]) {
        expect(
          await replayRefreshRotation(rotatedRow(overrides) as any, 'predecessor-token', now),
        ).toBeNull();
      }
      expect(Session.update).not.toHaveBeenCalled();
    });

    // An older ancestor's successor has itself rotated, so it is never answered.
    it('refuses when the successor is no longer the live head', async () => {
      const { Session, replayRefreshRotation } = await setUp({
        successor: buildSession({ ...successorRow(), replacedBySessionId: 'session-3' }),
      });

      expect(await replayRefreshRotation(rotatedRow() as any, 'predecessor-token', now)).toBeNull();
      expect(Session.update).not.toHaveBeenCalled();
    });

    it('refuses a sealed token that does not open, or opens to another token', async () => {
      let ctx = await setUp({ opened: null });
      expect(
        await ctx.replayRefreshRotation(rotatedRow() as any, 'predecessor-token', now),
      ).toBeNull();

      ctx = await setUp();
      const { createRefreshTokenLookup } = await import('../../../src/lib/token');
      (createRefreshTokenLookup as any).mockReturnValue('other-lookup');
      expect(
        await ctx.replayRefreshRotation(rotatedRow() as any, 'predecessor-token', now),
      ).toBeNull();
      expect(ctx.Session.update).not.toHaveBeenCalled();
    });

    it('refuses when the successor owner is gone', async () => {
      const { User, replayRefreshRotation } = await setUp();
      (User.findOne as any)
        .mockResolvedValueOnce({ id: 'user-1', sessionsRevokedBefore: null })
        .mockResolvedValueOnce(null);

      expect(await replayRefreshRotation(rotatedRow() as any, 'predecessor-token', now)).toBeNull();
    });

    it('refuses once the replays are spent', async () => {
      const { replayRefreshRotation } = await setUp({ claimed: 0 });

      expect(await replayRefreshRotation(rotatedRow() as any, 'predecessor-token', now)).toBeNull();
    });
  });

  it('refuses a replaced session without revoking the chain it was rotated into', async () => {
    const { Session } = await import('../../../src/models/sessions');
    const mod = await import('../../../src/services/sessionService');

    const session = buildSession({ replacedBySessionId: 'next-session' });
    (Session.findByPk as any).mockResolvedValue(session);

    const result = await mod.validateSessionRecord('id');

    expect(result).toBeNull();
    // Revoking here walked replacedBySessionId forward and killed the session that had
    // just been issued, signing the user out over an ordinary in-flight request.
    expect(session.save).not.toHaveBeenCalled();
    expect(Session.findByPk).not.toHaveBeenCalledWith('next-session');
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

  it('keeps the reason a row was already revoked for and clears its sealed replay token', async () => {
    const earlier = new Date(Date.now() - 60_000);
    const session = buildSession({
      replacedBySessionId: null,
      revokedAt: earlier,
      revokedReason: 'user_revoked',
      replayTokenCiphertext: 'sealed',
    });

    const { revokeSessionChain } = await import('../../../src/services/sessionService');

    await revokeSessionChain(session as any);

    expect(session.revokedAt).toBe(earlier);
    expect(session.revokedReason).toBe('user_revoked');
    expect(session.replayTokenCiphertext).toBeNull();
  });

  // A rotation can claim the head between the walk reading it and saving it as revoked.
  it('follows a link a rotation wrote while the head was being revoked', async () => {
    const { Session } = await import('../../../src/models/sessions');

    const head = buildSession({ id: 'head', replacedBySessionId: null });
    head.reload.mockImplementation(async () => {
      head.replacedBySessionId = 'late';
    });
    const late = buildSession({ id: 'late', replacedBySessionId: null });
    (Session.findByPk as any).mockResolvedValue(late);

    const { revokeSessionChain } = await import('../../../src/services/sessionService');

    await revokeSessionChain(head as any, 'user_revoked');

    expect(Session.findByPk).toHaveBeenCalledWith('late');
    expect(late.revokedReason).toBe('user_revoked');
    expect(late.save).toHaveBeenCalled();
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

  // Rotation reads, checks and links in separate statements, so two refreshes carrying the
  // same token both reach the link. The condition in the where clause is what decides
  // which of them rotated, in one statement the database serialises.
  it('claims the rotation link only while it is still unset', async () => {
    const { Session } = await import('../../../src/models/sessions');
    const session = buildSession({ id: 'session-1', replacedBySessionId: null });

    (Session.update as any).mockResolvedValue([1]);

    const { claimSessionRotation } = await import('../../../src/services/sessionService');

    expect(await claimSessionRotation(session as any, 'session-2')).toBe(true);
    expect(Session.update).toHaveBeenCalledWith(
      { replacedBySessionId: 'session-2' },
      { where: { id: 'session-1', replacedBySessionId: null, revokedAt: null } },
    );
    expect(session.replacedBySessionId).toBe('session-2');
  });

  it('reports the rotation lost when another one claimed the link first', async () => {
    const { Session } = await import('../../../src/models/sessions');
    const session = buildSession({ id: 'session-1', replacedBySessionId: null });

    (Session.update as any).mockResolvedValue([0]);

    const { claimSessionRotation } = await import('../../../src/services/sessionService');

    expect(await claimSessionRotation(session as any, 'session-2')).toBe(false);
    expect(session.replacedBySessionId).toBeNull();
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
      recovery: false,
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
    const { User } = await import('../../../src/models/users');
    (User.findOne as any).mockResolvedValue({ id: 'other', sessionsRevokedBefore: null });

    const { validateBearerToken } = await import('../../../src/services/sessionService');

    const result = await validateBearerToken('token');

    expect(result).toBeNull();
    // Refused on the subject check, not earlier for want of an owner row.
    expect(User.findOne).toHaveBeenCalledTimes(1);
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

    // No attempt id on a token minted before the claim existed.
    expect(result).toEqual({ user });
  });

  it('carries the ephemeral token jti as the attempt id, for real and decoy subjects', async () => {
    const jose = await import('jose');
    const { getPublicKeyByKid } = await import('../../../src/utils/signingKeyStore');
    const { User } = await import('../../../src/models/users');

    (getPublicKeyByKid as any).mockResolvedValue('pem');
    (jose.jwtVerify as any).mockResolvedValue({
      payload: { typ: 'ephemeral', sub: 'user', jti: 'attempt-1' },
    });

    const user = { id: 'user' };
    (User.findOne as any).mockResolvedValue(user);

    const { validateBearerToken } = await import('../../../src/services/sessionService');

    expect(await validateBearerToken('token', 'ephemeral')).toEqual({
      user,
      attemptId: 'attempt-1',
    });

    (User.findOne as any).mockResolvedValue(null);

    expect(await validateBearerToken('token', 'ephemeral')).toMatchObject({
      decoy: true,
      attemptId: 'attempt-1',
    });
  });

  it('carries the ephemeral token expiry, so a re-mint can keep it', async () => {
    const jose = await import('jose');
    const { getPublicKeyByKid } = await import('../../../src/utils/signingKeyStore');
    const { User } = await import('../../../src/models/users');

    (getPublicKeyByKid as any).mockResolvedValue('pem');
    (jose.jwtVerify as any).mockResolvedValue({
      payload: { typ: 'ephemeral', sub: 'user', jti: 'attempt-1', exp: 1_700_000_300 },
    });

    const user = { id: 'user' };
    (User.findOne as any).mockResolvedValue(user);

    const { validateBearerToken } = await import('../../../src/services/sessionService');

    expect(await validateBearerToken('token', 'ephemeral')).toEqual({
      user,
      attemptId: 'attempt-1',
      attemptExpiresAt: 1_700_000_300,
    });

    (User.findOne as any).mockResolvedValue(null);

    expect(await validateBearerToken('token', 'ephemeral')).toMatchObject({
      decoy: true,
      attemptExpiresAt: 1_700_000_300,
    });
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

  it('resolves an ephemeral subject with no matching user as a decoy', async () => {
    const jose = await import('jose');
    const { getPublicKeyByKid } = await import('../../../src/utils/signingKeyStore');
    const { User } = await import('../../../src/models/users');

    (getPublicKeyByKid as any).mockResolvedValue('pem');
    (jose.jwtVerify as any).mockResolvedValue({
      payload: { typ: 'ephemeral', sub: 'user' },
    });
    (User.findOne as any).mockResolvedValue(null);

    const { validateBearerToken } = await import('../../../src/services/sessionService');

    const result = await validateBearerToken('token', 'ephemeral');

    // Rejecting here is what used to move the enumeration oracle one request past
    // /login, so the token now continues as the decoy it was issued as.
    expect(result?.decoy).toBe(true);
    expect(result?.user.id).toBe('user');
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
    // The cutoff lookup finds the row; the revoked-user filter in getUserFromSession does not.
    (User.findOne as any)
      .mockResolvedValueOnce({ id: 'user', sessionsRevokedBefore: null })
      .mockResolvedValueOnce(null);

    const { validateBearerToken } = await import('../../../src/services/sessionService');

    expect(await validateBearerToken('token')).toBeNull();
    expect(User.findOne).toHaveBeenCalledTimes(2);
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

describe('exchanged sessions', () => {
  const future = new Date(Date.now() + 60_000);
  const childRow = {
    id: 'child-1',
    userId: 'user-1',
    parentSessionId: 'parent-1',
    expiresAt: future,
    idleExpiresAt: future,
    createdAt: new Date(),
  };

  beforeEach(async () => {
    const { User } = await import('../../../src/models/users');
    vi.mocked(User.findOne).mockResolvedValue({
      id: 'user-1',
      sessionsRevokedBefore: null,
    } as never);
  });

  it('refuses a child whose parent no longer resolves to a live session', async () => {
    const { Session } = await import('../../../src/models/sessions');
    const { resolveCurrentSession } = await import('../../../src/services/oidcAuthContext');
    const { validateSessionRecord } = await import('../../../src/services/sessionService');
    vi.mocked(Session.findByPk).mockResolvedValue(childRow as never);
    vi.mocked(resolveCurrentSession).mockResolvedValue(null);

    expect(await validateSessionRecord('child-1')).toBeNull();
    expect(resolveCurrentSession).toHaveBeenCalledWith('parent-1');
  });

  it('accepts a child whose parent is live', async () => {
    const { Session } = await import('../../../src/models/sessions');
    const { resolveCurrentSession } = await import('../../../src/services/oidcAuthContext');
    const { validateSessionRecord } = await import('../../../src/services/sessionService');
    vi.mocked(Session.findByPk).mockResolvedValue(childRow as never);
    vi.mocked(resolveCurrentSession).mockResolvedValue({ id: 'parent-now' } as never);

    expect(await validateSessionRecord('child-1')).toBe(childRow);
  });

  describe('revokeOrphanedChildSessions', () => {
    it('ends the children whose parent is gone, and only those', async () => {
      const { Session } = await import('../../../src/models/sessions');
      const { resolveCurrentSession } = await import('../../../src/services/oidcAuthContext');
      const { revokeOrphanedChildSessions } = await import('../../../src/services/sessionService');
      vi.mocked(Session.findAll).mockResolvedValue([
        { id: 'orphan', parentSessionId: 'gone' },
        { id: 'kept', parentSessionId: 'live' },
      ] as never);
      vi.mocked(resolveCurrentSession).mockImplementation((async (id: string) =>
        id === 'live' ? { id } : null) as never);

      await revokeOrphanedChildSessions({ userId: 'user-1', parentSessionId: null });

      expect(Session.update).toHaveBeenCalledTimes(1);
      expect(vi.mocked(Session.update).mock.calls[0][1]).toMatchObject({
        where: { id: 'orphan', revokedAt: null },
      });
      expect(vi.mocked(Session.update).mock.calls[0][0]).toMatchObject({
        revokedReason: 'parent_session_ended',
      });
    });

    it('does nothing for a session that is itself a child', async () => {
      const { Session } = await import('../../../src/models/sessions');
      const { revokeOrphanedChildSessions } = await import('../../../src/services/sessionService');

      await revokeOrphanedChildSessions({ userId: 'user-1', parentSessionId: 'parent-1' });

      expect(Session.findAll).not.toHaveBeenCalled();
    });

    it('never fails the revoke that caused it', async () => {
      const { Session } = await import('../../../src/models/sessions');
      const { revokeOrphanedChildSessions } = await import('../../../src/services/sessionService');
      vi.mocked(Session.findAll).mockRejectedValue(new Error('down'));

      await expect(
        revokeOrphanedChildSessions({ userId: 'user-1', parentSessionId: null }),
      ).resolves.toBeUndefined();
    });
  });
});
