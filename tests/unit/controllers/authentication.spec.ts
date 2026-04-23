/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
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
  vi.stubEnv('AUTH_MODE', 'server');

  const [
    { refreshSession },
    { getSystemConfig },
    { Session },
    { User },
    { AuthEventService },
    tokenLib,
    cookieLib,
    sessionService,
  ] = await Promise.all([
    import('../../../src/controllers/authentication.js'),
    import('../../../src/config/getSystemConfig.js'),
    import('../../../src/models/sessions.js'),
    import('../../../src/models/users.js'),
    import('../../../src/services/authEventService.js'),
    import('../../../src/lib/token.js'),
    import('../../../src/lib/cookie.js'),
    import('../../../src/services/sessionService.js'),
  ]);

  return {
    refreshSession,
    getSystemConfig,
    Session,
    User,
    AuthEventService,
    findRefreshSessionByToken: sessionService.findRefreshSessionByToken,
    generateRefreshToken: tokenLib.generateRefreshToken,
    hashRefreshToken: tokenLib.hashRefreshToken,
    createRefreshTokenLookup: tokenLib.createRefreshTokenLookup,
    signAccessToken: tokenLib.signAccessToken,
    setAuthCookies: cookieLib.setAuthCookies,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe('refreshSession', () => {
  it('rejects missing refresh token in server mode', async () => {
    const { refreshSession, AuthEventService } = await loadAuthenticationModule();
    const { req, res } = mockReqRes();

    await refreshSession(req, res);

    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: null,
        type: 'refresh_token_failed',
        metadata: { reason: 'Missing refresh token' },
      }),
    );
    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'Not allowed' });
  });

  it('rotates the session using the raw bearer refresh token in server mode', async () => {
    const {
      refreshSession,
      getSystemConfig,
      Session,
      User,
      findRefreshSessionByToken,
      generateRefreshToken,
      hashRefreshToken,
      createRefreshTokenLookup,
      signAccessToken,
      setAuthCookies,
    } = await loadAuthenticationModule();
    const { req, res } = mockReqRes('Bearer raw-refresh-token');
    const user = buildUser({ id: 'user-1', roles: ['admin'] });
    const session = {
      id: 'session-1',
      refreshTokenHash: 'stored-refresh-hash',
      replacedBySessionId: null,
      revokedAt: null,
      userId: user.id,
      infraId: 'app',
      mode: 'server',
      userAgent: 'vitest',
      save: vi.fn(),
    };

    (findRefreshSessionByToken as any).mockResolvedValue({
      session,
      legacyFallbackCandidates: 0,
      usedLegacyFallback: false,
    });
    (User.findByPk as any).mockResolvedValue(user);
    (generateRefreshToken as any).mockReturnValue('new-raw-refresh-token');
    (hashRefreshToken as any).mockResolvedValue('new-refresh-hash');
    (createRefreshTokenLookup as any).mockReturnValue('new-refresh-lookup');
    (Session.create as any).mockResolvedValue({ id: 'session-2' });
    (signAccessToken as any).mockResolvedValue('new-access-token');
    (getSystemConfig as any).mockResolvedValue({
      access_token_ttl: '15m',
      refresh_token_ttl: '1h',
    });

    await refreshSession(req, res);

    expect(findRefreshSessionByToken).toHaveBeenCalledWith('raw-refresh-token', expect.any(Date));
    expect(Session.create).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: user.id,
        refreshTokenHash: 'new-refresh-hash',
        refreshTokenLookup: 'new-refresh-lookup',
      }),
    );
    expect(signAccessToken).toHaveBeenCalledWith('session-2', user.id, user.roles);
    expect(setAuthCookies).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith({
      message: 'Success',
      token: 'new-access-token',
      refreshToken: 'new-raw-refresh-token',
      sub: user.id,
      roles: user.roles,
      email: user.email,
      phone: user.phone,
      ttl: 900,
      refreshTtl: 3600,
    });
  });
});
