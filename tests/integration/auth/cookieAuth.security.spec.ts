import { beforeEach, describe, expect, it, vi } from 'vitest';
import { compareSync } from 'bcrypt-ts';

import { verifyCookieAuth } from '../../../src/middleware/verifyCookieAuth.js';
import { clearAuthCookies, setAuthCookies } from '../../../src/lib/cookie.js';
import { Session } from '../../../src/models/sessions.js';
import { User } from '../../../src/models/users.js';
import { AuthEventService } from '../../../src/services/authEventService.js';
import {
  getUserFromSession,
  hardRevokeSession,
  revokeSessionChain,
  validateAccessToken,
  validateSessionRecord,
  verifyJwtWithKid,
} from '../../../src/services/sessionService.js';
import { generateRefreshToken, hashRefreshToken, signAccessToken } from '../../../src/lib/token.js';

function mockReqRes(cookies: Record<string, string> = {}) {
  const req: any = {
    cookies,
    ip: '127.0.0.1',
    headers: { 'user-agent': 'vitest' },
    get: vi.fn((name: string) => {
      if (name.toLowerCase() === 'user-agent') return 'vitest';
      return undefined;
    }),
  };

  const res: any = {
    status: vi.fn().mockReturnThis(),
    json: vi.fn().mockReturnThis(),
  };

  const next = vi.fn();

  return { req, res, next };
}

function buildRefreshSession(overrides: Record<string, unknown> = {}) {
  return {
    id: 'session-1',
    userId: 'user-1',
    infraId: 'app-1',
    mode: 'web',
    refreshTokenHash: 'hashed-refresh',
    userAgent: 'vitest',
    ipAddress: '127.0.0.1',
    replacedBySessionId: null,
    revokedAt: null,
    save: vi.fn(),
    ...overrides,
  };
}

beforeEach(() => {
  vi.clearAllMocks();

  (compareSync as any).mockReturnValue(false);

  (generateRefreshToken as any).mockReturnValue('new-refresh-token');
  (hashRefreshToken as any).mockResolvedValue('new-refresh-hash');
  (signAccessToken as any).mockResolvedValue('new-access-token');

  (Session.create as any).mockResolvedValue({ id: 'session-2' });
});

describe('verifyCookieAuth security - ephemeral', () => {
  it('returns 401 and clears cookies when ephemeral cookie is missing', async () => {
    const middleware = verifyCookieAuth('ephemeral');
    const { req, res, next } = mockReqRes();

    await middleware(req, res, next);

    expect(clearAuthCookies).toHaveBeenCalledWith(res);
    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'unauthorized' });
    expect(next).not.toHaveBeenCalled();
  });

  it('returns 401 when ephemeral jwt is invalid', async () => {
    (verifyJwtWithKid as any).mockResolvedValue(null);

    const middleware = verifyCookieAuth('ephemeral');
    const { req, res, next } = mockReqRes({
      seamless_ephemeral: 'bad-token',
    });

    await middleware(req, res, next);

    expect(clearAuthCookies).toHaveBeenCalledWith(res);
    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'unauthorized' });
    expect(next).not.toHaveBeenCalled();
  });
});

describe('verifyCookieAuth security - access path', () => {
  it('returns 401 when access token is valid structurally but session record is invalid', async () => {
    (validateAccessToken as any).mockResolvedValue({ sessionId: 'session-1' });
    (validateSessionRecord as any).mockResolvedValue(null);

    const middleware = verifyCookieAuth('access');
    const { req, res, next } = mockReqRes({
      seamless_access: 'access-token',
    });

    await middleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(next).not.toHaveBeenCalled();
  });

  it('returns 401 when access token session resolves but user lookup fails', async () => {
    (validateAccessToken as any).mockResolvedValue({ sessionId: 'session-1' });
    (validateSessionRecord as any).mockResolvedValue({ id: 'session-1' });
    (getUserFromSession as any).mockResolvedValue(null);

    const middleware = verifyCookieAuth('access');
    const { req, res, next } = mockReqRes({
      seamless_access: 'access-token',
    });

    await middleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(next).not.toHaveBeenCalled();
  });
});

describe('verifyCookieAuth security - silent refresh', () => {
  it('returns 401 when refresh cookie is present but no matching session is found', async () => {
    (validateAccessToken as any).mockResolvedValue(null);
    (Session.findAll as any).mockResolvedValue([]);
    (AuthEventService.serviceTokenInvalid as any).mockResolvedValue(undefined);

    const middleware = verifyCookieAuth('access');
    const { req, res, next } = mockReqRes({
      seamless_refresh: 'refresh-token',
    });

    await middleware(req, res, next);

    expect(AuthEventService.serviceTokenInvalid).toHaveBeenCalledWith(req);
    expect(res.status).toHaveBeenCalledWith(401);
    expect(next).not.toHaveBeenCalled();
  });

  it('detects refresh token reuse when session was already replaced', async () => {
    (validateAccessToken as any).mockResolvedValue(null);
    (compareSync as any).mockReturnValue(true);

    const reusedSession = buildRefreshSession({
      replacedBySessionId: 'session-2',
    });

    (Session.findAll as any).mockResolvedValue([reusedSession]);
    (revokeSessionChain as any).mockResolvedValue(undefined);
    (AuthEventService.serviceTokenInvalid as any).mockResolvedValue(undefined);

    const middleware = verifyCookieAuth('access');
    const { req, res, next } = mockReqRes({
      seamless_refresh: 'refresh-token',
    });

    await middleware(req, res, next);

    expect(revokeSessionChain).toHaveBeenCalledWith(reusedSession);
    expect(AuthEventService.serviceTokenInvalid).toHaveBeenCalledWith(req);
    expect(res.status).toHaveBeenCalledWith(401);
    expect(next).not.toHaveBeenCalled();
  });

  it('detects refresh token reuse when session is already revoked', async () => {
    (validateAccessToken as any).mockResolvedValue(null);
    (compareSync as any).mockReturnValue(true);

    const revokedSession = buildRefreshSession({
      revokedAt: new Date(),
    });

    (Session.findAll as any).mockResolvedValue([revokedSession]);
    (revokeSessionChain as any).mockResolvedValue(undefined);
    (AuthEventService.serviceTokenInvalid as any).mockResolvedValue(undefined);

    const middleware = verifyCookieAuth('access');
    const { req, res, next } = mockReqRes({
      seamless_refresh: 'refresh-token',
    });

    await middleware(req, res, next);

    expect(revokeSessionChain).toHaveBeenCalledWith(revokedSession);
    expect(res.status).toHaveBeenCalledWith(401);
    expect(next).not.toHaveBeenCalled();
  });

  it('hard-revokes when refresh session user no longer exists', async () => {
    (validateAccessToken as any).mockResolvedValue(null);
    (compareSync as any).mockReturnValue(true);

    const session = buildRefreshSession();

    (Session.findAll as any).mockResolvedValue([session]);
    (User.findByPk as any).mockResolvedValue(null);
    (hardRevokeSession as any).mockResolvedValue(undefined);

    const middleware = verifyCookieAuth('access');
    const { req, res, next } = mockReqRes({
      seamless_refresh: 'refresh-token',
    });

    await middleware(req, res, next);

    expect(hardRevokeSession).toHaveBeenCalledWith(session, 'user_not_found');
    expect(res.status).toHaveBeenCalledWith(401);
    expect(next).not.toHaveBeenCalled();
  });

  it('rotates session and sets fresh cookies on successful refresh', async () => {
    (validateAccessToken as any).mockResolvedValue(null);
    (compareSync as any).mockReturnValue(true);

    const session = buildRefreshSession();

    (Session.findAll as any).mockResolvedValue([session]);
    (User.findByPk as any).mockResolvedValue({ id: 'user-1' });

    const middleware = verifyCookieAuth('access');
    const { req, res, next } = mockReqRes({
      seamless_refresh: 'refresh-token',
    });

    await middleware(req, res, next);

    expect(Session.create).toHaveBeenCalled();
    expect(session.save).toHaveBeenCalled();
    expect(setAuthCookies).toHaveBeenCalledWith(
      res,
      expect.objectContaining({
        accessToken: 'new-access-token',
        refreshToken: 'new-refresh-token',
      }),
    );
    expect(next).toHaveBeenCalled();
  });
});
