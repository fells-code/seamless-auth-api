/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { beforeEach, describe, expect, it, vi } from 'vitest';

import { buildUser } from '../../factories/userFactory.js';

function mockReqRes(authorization?: string) {
  const req: any = {
    ip: '127.0.0.1',
    cookies: {},
    headers: {
      'user-agent': 'vitest',
      ...(authorization ? { authorization } : {}),
    },
  };

  const res: any = {
    status: vi.fn().mockReturnThis(),
    json: vi.fn().mockReturnThis(),
  };

  return { req, res };
}

async function loadAuthenticationModule() {
  const [
    { refreshSession },
    { getSystemConfig },
    { Session },
    { User },
    { AuthEventService },
    tokenLib,
    sessionService,
  ] = await Promise.all([
    import('../../../src/controllers/authentication.js'),
    import('../../../src/config/getSystemConfig.js'),
    import('../../../src/models/sessions.js'),
    import('../../../src/models/users.js'),
    import('../../../src/services/authEventService.js'),
    import('../../../src/lib/token.js'),
    import('../../../src/services/sessionService.js'),
  ]);

  return {
    refreshSession,
    getSystemConfig,
    Session,
    User,
    AuthEventService,
    findRefreshSessionByToken: sessionService.findRefreshSessionByToken,
    classifyExpiredRefreshToken: sessionService.classifyExpiredRefreshToken,
    hardRevokeSession: sessionService.hardRevokeSession,
    generateRefreshToken: tokenLib.generateRefreshToken,
    createRefreshTokenLookup: tokenLib.createRefreshTokenLookup,
    signAccessToken: tokenLib.signAccessToken,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe('refreshSession', () => {
  it('rejects missing refresh token', async () => {
    const { refreshSession, AuthEventService } = await loadAuthenticationModule();
    const { req, res } = mockReqRes();

    await refreshSession(req, res);

    expect(AuthEventService.refreshTokenFailed).toHaveBeenCalledWith(
      req,
      expect.objectContaining({
        reason: 'Missing refresh token',
      }),
    );
    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'Not allowed' });
  });

  it('rejects refresh tokens that do not resolve to a session', async () => {
    const { refreshSession, AuthEventService, findRefreshSessionByToken } =
      await loadAuthenticationModule();
    const { req, res } = mockReqRes('Bearer raw-refresh-token');

    (findRefreshSessionByToken as any).mockResolvedValue(null);
    (AuthEventService.refreshTokenFailed as any).mockResolvedValue(undefined);

    await refreshSession(req, res);

    expect(findRefreshSessionByToken).toHaveBeenCalledWith('raw-refresh-token', expect.any(Date));
    expect(AuthEventService.refreshTokenFailed).toHaveBeenCalledWith(
      req,
      expect.objectContaining({
        reason: 'No refresh session found for refresh token',
        tokenFormat: 'opaque',
      }),
    );
    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'invalid_refresh_token' });
  });

  it('rotates the session using the raw bearer refresh token', async () => {
    const {
      refreshSession,
      getSystemConfig,
      Session,
      User,
      findRefreshSessionByToken,
      generateRefreshToken,
      createRefreshTokenLookup,
      signAccessToken,
    } = await loadAuthenticationModule();
    const { req, res } = mockReqRes('Bearer raw-refresh-token');
    const user = buildUser({ id: 'user-1', roles: ['admin'] });
    const session = {
      id: 'session-1',
      replacedBySessionId: null,
      revokedAt: null,
      userId: user.id,
      infraId: 'app',
      mode: 'server',
      userAgent: 'vitest',
      save: vi.fn(),
    };

    (findRefreshSessionByToken as any).mockResolvedValue(session);
    (User.findOne as any).mockResolvedValue(user);
    (generateRefreshToken as any).mockReturnValue('new-raw-refresh-token');
    (createRefreshTokenLookup as any).mockReturnValue('new-refresh-lookup');
    (Session.create as any).mockResolvedValue({ id: 'session-2' });
    (signAccessToken as any).mockResolvedValue('new-access-token');
    (getSystemConfig as any).mockResolvedValue({
      access_token_ttl: '15m',
      refresh_token_ttl: '1h',
      session_idle_ttl: '8h',
    });

    await refreshSession(req, res);

    expect(findRefreshSessionByToken).toHaveBeenCalledWith('raw-refresh-token', expect.any(Date));
    expect(Session.create).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: user.id,
        refreshTokenLookup: 'new-refresh-lookup',
      }),
    );
    expect(signAccessToken).toHaveBeenCalledWith('session-2', user.id, user.roles, undefined);
    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith({
      message: 'Success',
      token: 'new-access-token',
      refreshToken: 'new-raw-refresh-token',
      sub: user.id,
      roles: user.roles,
      organizationId: undefined,
      sessionId: 'session-2',
      email: user.email,
      phone: user.phone,
      ttl: 900,
      refreshTtl: 3600,
    });
  });
  describe('absolute session lifetime', () => {
    const hour = 60 * 60 * 1000;

    async function setUpRotation(sessionOverrides: Record<string, unknown>) {
      const mod = await loadAuthenticationModule();
      const user = buildUser({ id: 'user-1', roles: ['user'] });
      const session = {
        id: 'session-1',
        replacedBySessionId: null,
        revokedAt: null,
        userId: user.id,
        organizationId: null,
        userAgent: 'vitest',
        save: vi.fn(),
        ...sessionOverrides,
      };

      (mod.findRefreshSessionByToken as any).mockResolvedValue(session);
      (mod.User.findOne as any).mockResolvedValue(user);
      (mod.generateRefreshToken as any).mockReturnValue('new-raw-refresh-token');
      (mod.createRefreshTokenLookup as any).mockReturnValue('new-refresh-lookup');
      (mod.Session.create as any).mockResolvedValue({ id: 'session-2' });
      (mod.signAccessToken as any).mockResolvedValue('new-access-token');
      (mod.getSystemConfig as any).mockResolvedValue({
        access_token_ttl: '15m',
        refresh_token_ttl: '1d',
        session_idle_ttl: '8h',
      });

      return { ...mod, session };
    }

    it('carries the chain start forward so a refresh cannot extend the session', async () => {
      const chainStartedAt = new Date(Date.now() - 20 * hour);
      const { refreshSession, Session } = await setUpRotation({ chainStartedAt });
      const { req, res } = mockReqRes('Bearer raw-refresh-token');

      await refreshSession(req, res);

      const created = (Session.create as any).mock.calls[0][0];
      expect(created.chainStartedAt).toBe(chainStartedAt);
      expect(created.expiresAt.getTime()).toBe(chainStartedAt.getTime() + 24 * hour);
      expect(created.idleExpiresAt.getTime()).toBe(created.expiresAt.getTime());
      expect(res.status).toHaveBeenCalledWith(200);
    });

    it('reports only what is left of the chain as the refresh lifetime', async () => {
      const chainStartedAt = new Date(Date.now() - 20 * hour);
      const { refreshSession } = await setUpRotation({ chainStartedAt });
      const { req, res } = mockReqRes('Bearer raw-refresh-token');

      await refreshSession(req, res);

      const { refreshTtl } = res.json.mock.calls[0][0];
      expect(refreshTtl).toBeGreaterThan(4 * 60 * 60 - 5);
      expect(refreshTtl).toBeLessThanOrEqual(4 * 60 * 60);
    });

    it('falls back to the row creation time for sessions issued before the chain was tracked', async () => {
      const createdAt = new Date(Date.now() - 2 * hour);
      const { refreshSession, Session } = await setUpRotation({ chainStartedAt: null, createdAt });
      const { req, res } = mockReqRes('Bearer raw-refresh-token');

      await refreshSession(req, res);

      expect((Session.create as any).mock.calls[0][0].chainStartedAt).toBe(createdAt);
    });

    it('refuses to rotate a chain the absolute lifetime has already passed', async () => {
      const chainStartedAt = new Date(Date.now() - 25 * hour);
      const { refreshSession, Session, AuthEventService, hardRevokeSession, session } =
        await setUpRotation({ chainStartedAt });
      const { req, res } = mockReqRes('Bearer raw-refresh-token');

      await refreshSession(req, res);

      expect(Session.create).not.toHaveBeenCalled();
      expect(hardRevokeSession).toHaveBeenCalledWith(session, 'absolute_lifetime_reached');
      expect(AuthEventService.log).toHaveBeenCalledWith(
        expect.objectContaining({
          type: 'refresh_token_failed',
          userId: 'user-1',
          sessionId: 'session-1',
          metadata: expect.objectContaining({ refusal: 'absolute_lifetime_reached' }),
        }),
      );
      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({ error: 'invalid_refresh_token' });
    });

    it('records an expired chain distinctly from an unknown token', async () => {
      const {
        refreshSession,
        AuthEventService,
        findRefreshSessionByToken,
        classifyExpiredRefreshToken,
      } = await loadAuthenticationModule();
      const { req, res } = mockReqRes('Bearer raw-refresh-token');
      const chainStartedAt = new Date(Date.now() - 25 * hour);

      (findRefreshSessionByToken as any).mockResolvedValue(null);
      (classifyExpiredRefreshToken as any).mockResolvedValue({
        reason: 'absolute_lifetime_reached',
        session: { id: 'session-1', userId: 'user-1', chainStartedAt },
      });

      await refreshSession(req, res);

      expect(AuthEventService.refreshTokenFailed).not.toHaveBeenCalled();
      expect(AuthEventService.log).toHaveBeenCalledWith(
        expect.objectContaining({
          type: 'refresh_token_failed',
          userId: 'user-1',
          sessionId: 'session-1',
          metadata: {
            reason: 'Session absolute lifetime reached',
            refusal: 'absolute_lifetime_reached',
            chainStartedAt: chainStartedAt.toISOString(),
          },
        }),
      );
      expect(res.json).toHaveBeenCalledWith({ error: 'invalid_refresh_token' });
    });
  });
});
