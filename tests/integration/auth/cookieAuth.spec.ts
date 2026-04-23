import { describe, it, expect, beforeEach, vi } from 'vitest';
import { verifyCookieAuth } from '../../../src/middleware/verifyCookieAuth.js';
import { clearAuthCookies } from '../../../src/lib/cookie.js';

import {
  validateAccessToken,
  validateSessionRecord,
  getUserFromSession,
  verifyJwtWithKid,
} from '../../../src/services/sessionService.js';

vi.mock('../../../src/models/authEvents.js', () => ({
  AuthEvent: {
    create: vi.fn(),
  },
}));

vi.mock('bcrypt-ts', () => ({
  compareSync: vi.fn(),
}));

import { User } from '../../../src/models/users.js';
import { Session } from '../../../src/models/sessions.js';
import { generateRefreshToken, hashRefreshToken, signAccessToken } from '../../../src/lib/token.js';
import { compareSync } from 'bcrypt-ts';

function mockReqRes(cookies: any = {}) {
  const req: any = {
    cookies,
    ip: '127.0.0.1',
    headers: {},
  };

  const res: any = {
    status: vi.fn().mockReturnThis(),
    json: vi.fn(),
  };

  const next = vi.fn();

  return { req, res, next };
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe('verifyCookieAuth - ephemeral', () => {
  it('rejects missing cookie', async () => {
    const middleware = verifyCookieAuth('ephemeral');
    const { req, res, next } = mockReqRes();

    await middleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
  });

  it('accepts valid ephemeral token', async () => {
    (verifyJwtWithKid as any).mockResolvedValue({ sub: 'user-1' });

    (User.findOne as any).mockResolvedValue({
      id: 'user-1',
      revoked: false,
    });

    const middleware = verifyCookieAuth('ephemeral');

    const { req, res, next } = mockReqRes({
      seamless_ephemeral: 'token',
    });

    await middleware(req, res, next);

    expect(req.user).toBeDefined();
    expect(next).toHaveBeenCalled();
  });

  it('rejects invalid ephemeral token with 401', async () => {
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

describe('verifyCookieAuth - access token', () => {
  it('uses valid access token', async () => {
    (validateAccessToken as any).mockResolvedValue({
      sessionId: 'session-1',
    });

    (validateSessionRecord as any).mockResolvedValue({
      id: 'session-1',
    });

    (getUserFromSession as any).mockResolvedValue({
      id: 'user-1',
    });

    const middleware = verifyCookieAuth('access');

    const { req, res, next } = mockReqRes({
      seamless_access: 'access-token',
    });

    await middleware(req, res, next);

    expect(req.user).toBeDefined();
    expect(next).toHaveBeenCalled();
  });

  it('returns 401 when no cookies', async () => {
    const middleware = verifyCookieAuth('access');

    const { req, res, next } = mockReqRes();

    await middleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
  });
});

describe('verifyCookieAuth - silent refresh', () => {
  it('refreshes session when access token invalid', async () => {
    (validateAccessToken as any).mockResolvedValue(null);

    (compareSync as any).mockReturnValue(true);

    (Session.findAll as any).mockResolvedValue([
      {
        id: 'session-1',
        refreshTokenHash: 'hash',
        userId: 'user-1',
        infraId: 'app',
        mode: 'web',
        userAgent: 'agent',
        replacedBySessionId: null,
        revokedAt: null,
        save: vi.fn(),
      },
    ]);

    (User.findByPk as any).mockResolvedValue({
      id: 'user-1',
    });

    (generateRefreshToken as any).mockReturnValue('refresh-token');
    (hashRefreshToken as any).mockResolvedValue('hashed-refresh');
    (signAccessToken as any).mockResolvedValue('access-token');

    (Session.create as any).mockResolvedValue({
      id: 'new-session',
    });

    const middleware = verifyCookieAuth('access');

    const { req, res, next } = mockReqRes({
      seamless_refresh: 'refresh-token',
    });

    await middleware(req, res, next);

    expect(next).toHaveBeenCalled();
  });
});
