import request from 'supertest';
import { describe, it, expect, beforeAll, beforeEach, vi } from 'vitest';
import { getSystemConfig } from '../../../src/config/getSystemConfig';
import { Application } from 'express';
import { Credential } from '../../../src/models/credentials';
import { createApp } from '../../../src/app';
import { Session } from '../../../src/models/sessions';
import { User } from '../../../src/models/users';
import { buildUser } from '../../factories/userFactory';
import {
  createRefreshTokenLookup,
  generateRefreshToken,
  hashRefreshToken,
  signAccessToken,
  signEphemeralToken,
} from '../../../src/lib/token';
import {
  findRefreshSessionByToken,
  hardRevokeSession,
  revokeSessionChain,
} from '../../../src/services/sessionService';
import { AuthEvent } from '../../../src/models/authEvents';
import { logoutCurrentSession } from '../../../src/controllers/authentication';

let app: Application;

function buildRes() {
  const res: any = {};
  res.status = vi.fn().mockReturnValue(res);
  res.json = vi.fn().mockReturnValue(res);
  return res;
}

function buildReq(overrides: Record<string, unknown> = {}) {
  return {
    body: {},
    ip: '127.0.0.1',
    headers: {},
    get: () => undefined,
    ...overrides,
  } as any;
}

vi.mock('../../../src/middleware/attachAuthMiddleware.js', async (importOriginal) => {
  const actual =
    await importOriginal<typeof import('../../../src/middleware/attachAuthMiddleware.js')>();

  return {
    ...actual,
    attachAuthMiddleware: () => (req: any, _res: any, next: any) => {
      req.user = buildUser();
      req.sessionId = 'session-1';
      next();
    },
  };
});

beforeAll(async () => {
  app = await createApp();
});

beforeEach(() => {
  vi.resetModules();
  vi.clearAllMocks();
  (AuthEvent.count as any).mockResolvedValue(0);
});

describe('POST /login', () => {
  it('rejects missing identifier', async () => {
    const res = await request(app).post('/login').send({ identifier: '' });

    expect(res.status).toBe(403);
  });

  it('rejects invalid identifier', async () => {
    const res = await request(app).post('/login').send({ identifier: 'bad' });

    expect(res.status).toBe(400);
  });

  it('rejects user not found', async () => {
    (User.findOne as any).mockResolvedValue(null);

    const res = await request(app).post('/login').send({ identifier: 'test@example.com' });

    expect(res.status).toBe(401);
  });

  it('rejects unverified user', async () => {
    (User.findOne as any).mockResolvedValue(buildUser({ verified: false }));

    const res = await request(app).post('/login').send({ identifier: 'test@example.com' });

    expect(res.status).toBe(401);
  });

  it('rejects passkey required but missing credential', async () => {
    (User.findOne as any).mockResolvedValue(buildUser({ verified: true }));
    (Credential.findOne as any).mockResolvedValue(null);
    (getSystemConfig as any).mockResolvedValue({
      access_token_ttl: '15m',
      login_methods: ['passkey'],
      passkey_login_fallback_enabled: false,
    });

    const res = await request(app).post('/login').send({
      identifier: 'test@example.com',
      passkeyAvailable: true,
    });

    expect(res.status).toBe(401);
    expect(res.body).toEqual({ error: 'Not Allowed' });
  });

  it('logs in successfully', async () => {
    (User.findOne as any).mockResolvedValue(buildUser({ verified: true }));
    (Credential.findOne as any).mockResolvedValue({});

    (signEphemeralToken as any).mockResolvedValue('token');

    (getSystemConfig as any).mockResolvedValue({
      access_token_ttl: '15m',
    });

    const res = await request(app).post('/login').send({
      identifier: 'test@example.com',
    });

    expect(res.status).toBe(200);
    expect(res.body.loginMethods).toEqual(['passkey', 'magic_link']);
  });

  it('returns administrator-enabled OTP login methods', async () => {
    (User.findOne as any).mockResolvedValue(buildUser({ verified: true }));
    (Credential.findOne as any).mockResolvedValue(null);

    (signEphemeralToken as any).mockResolvedValue('token');

    (getSystemConfig as any).mockResolvedValue({
      access_token_ttl: '15m',
      login_methods: ['email_otp', 'phone_otp'],
      passkey_login_fallback_enabled: true,
    });

    const res = await request(app).post('/login').send({
      identifier: 'test@example.com',
      passkeyAvailable: true,
    });

    expect(res.status).toBe(200);
    expect(res.body.loginMethods).toEqual(['email_otp', 'phone_otp']);
  });

  it('hides fallback methods when passkey fallback is disabled and passkey is available', async () => {
    (User.findOne as any).mockResolvedValue(buildUser({ verified: true }));
    (Credential.findOne as any).mockResolvedValue({});

    (signEphemeralToken as any).mockResolvedValue('token');

    (getSystemConfig as any).mockResolvedValue({
      access_token_ttl: '15m',
      login_methods: ['passkey', 'magic_link', 'email_otp', 'phone_otp'],
      passkey_login_fallback_enabled: false,
    });

    const res = await request(app).post('/login').send({
      identifier: 'test@example.com',
      passkeyAvailable: true,
    });

    expect(res.status).toBe(200);
    expect(res.body.loginMethods).toEqual(['passkey']);
  });

  it('resolves a user by phone identifier', async () => {
    (User.findOne as any).mockResolvedValue(buildUser({ verified: true }));
    (Credential.findOne as any).mockResolvedValue({});
    (signEphemeralToken as any).mockResolvedValue('token');
    (getSystemConfig as any).mockResolvedValue({ access_token_ttl: '15m' });

    const res = await request(app).post('/login').send({ identifier: '+14155552671' });

    expect(res.status).toBe(200);
    expect(res.body.identifierType).toBe('phone');
    expect(User.findOne).toHaveBeenCalledWith({ where: { phone: expect.any(String) } });
  });

  it('reports a server error when the email lookup throws', async () => {
    (User.findOne as any).mockRejectedValue(new Error('db down'));

    const res = await request(app).post('/login').send({ identifier: 'test@example.com' });

    expect(res.status).toBe(500);
    expect(res.body.error).toBe('Server error');
  });

  it('rejects uniformly when the ephemeral token cannot be signed', async () => {
    (User.findOne as any).mockResolvedValue(buildUser({ verified: true }));
    (Credential.findOne as any).mockResolvedValue({});
    (signEphemeralToken as any).mockResolvedValue(null);
    (getSystemConfig as any).mockResolvedValue({ access_token_ttl: '15m' });

    const res = await request(app).post('/login').send({ identifier: 'test@example.com' });

    expect(res.status).toBe(401);
    expect(res.body).toEqual({ error: 'Not Allowed' });
  });

  it('returns 500 when the post-identifier flow throws', async () => {
    (User.findOne as any).mockResolvedValue(buildUser({ verified: true }));
    (signEphemeralToken as any).mockResolvedValue('token');
    (Credential.findOne as any).mockRejectedValue(new Error('boom'));

    const res = await request(app).post('/login').send({ identifier: 'test@example.com' });

    expect(res.status).toBe(500);
    expect(res.body.error).toBe('Server error');
  });

  it('returns 500 when the post-identifier flow throws a non-error', async () => {
    (User.findOne as any).mockResolvedValue(buildUser({ verified: true }));
    (signEphemeralToken as any).mockResolvedValue('token');
    (Credential.findOne as any).mockRejectedValue('boom');

    const res = await request(app).post('/login').send({ identifier: 'test@example.com' });

    expect(res.status).toBe(500);
    expect(res.body.error).toBe('Server error');
  });

  it('reports a server error when the phone lookup throws, matching the email branch', async () => {
    (User.findOne as any).mockRejectedValue(new Error('db down'));

    const res = await request(app).post('/login').send({ identifier: '+14155552671' });

    expect(res.status).toBe(500);
    expect(res.body.error).toBe('Server error');
  });

  it('answers identically for unknown, unverified, and no-method identifiers', async () => {
    const responses: { status: number; body: unknown }[] = [];

    // Unknown identifier.
    (User.findOne as any).mockResolvedValue(null);
    responses.push(await request(app).post('/login').send({ identifier: 'nobody@example.com' }));

    // Known but unverified.
    (User.findOne as any).mockResolvedValue(buildUser({ verified: false }));
    (signEphemeralToken as any).mockResolvedValue('token');
    responses.push(
      await request(app).post('/login').send({ identifier: 'unverified@example.com' }),
    );

    // Verified, but the policy leaves no permitted continuation method.
    (User.findOne as any).mockResolvedValue(buildUser({ verified: true }));
    (Credential.findOne as any).mockResolvedValue(null);
    (getSystemConfig as any).mockResolvedValue({
      access_token_ttl: '15m',
      login_methods: ['passkey'],
      passkey_login_fallback_enabled: false,
    });
    responses.push(await request(app).post('/login').send({ identifier: 'nomethods@example.com' }));

    const shapes = responses.map((res) => ({ status: res.status, body: res.body }));

    expect(shapes[0]).toEqual({ status: 401, body: { error: 'Not Allowed' } });
    expect(shapes[1]).toEqual(shapes[0]);
    expect(shapes[2]).toEqual(shapes[0]);
  });

  it('rejects login for a locked account', async () => {
    (User.findOne as any).mockResolvedValue(buildUser({ verified: true }));
    (AuthEvent.count as any).mockResolvedValue(10);
    (getSystemConfig as any).mockResolvedValue({
      lockout_policy: { enabled: true, maxFailures: 10, windowSeconds: 900, lockoutSeconds: 900 },
    });

    const res = await request(app).post('/login').send({ identifier: 'test@example.com' });

    expect(res.status).toBe(423);
    expect(res.body.error).toBe('account_locked');
  });

  it('logs in with default TTL when no access token TTL is configured', async () => {
    (User.findOne as any).mockResolvedValue(buildUser({ verified: true }));
    (Credential.findOne as any).mockResolvedValue({});
    (signEphemeralToken as any).mockResolvedValue('token');
    (getSystemConfig as any).mockResolvedValue({});

    const res = await request(app).post('/login').send({ identifier: 'test@example.com' });

    expect(res.status).toBe(200);
    expect(res.body.ttl).toBe(900);
  });
});

describe('GET /logout', () => {
  it('logs out all user sessions for backward compatibility', async () => {
    const sessions = [{ id: 'session-1' }, { id: 'session-2' }];
    (Session.findAll as any).mockResolvedValue(sessions);

    const res = await request(app).get('/logout');

    expect(res.status).toBe(200);
    expect(res.body.message).toBe('Success');
    expect(hardRevokeSession).toHaveBeenCalledTimes(2);
    expect(hardRevokeSession).toHaveBeenNthCalledWith(1, sessions[0], 'user_logout_all');
    expect(hardRevokeSession).toHaveBeenNthCalledWith(2, sessions[1], 'user_logout_all');
  });
});

describe('DELETE /logout', () => {
  it('logs out only the current session', async () => {
    const session = { id: 'session-1', userId: 'user-1' };
    (Session.findOne as any).mockResolvedValue(session);

    const res = await request(app).delete('/logout');

    expect(res.status).toBe(200);
    expect(res.body.message).toBe('Success');
    expect(Session.findOne).toHaveBeenCalledWith({
      where: { id: 'session-1', userId: expect.any(String), revokedAt: null },
    });
    expect(hardRevokeSession).toHaveBeenCalledWith(session, 'user_logout');
  });

  it('succeeds without revoking when no active session is found', async () => {
    (Session.findOne as any).mockResolvedValue(null);

    const res = await request(app).delete('/logout');

    expect(res.status).toBe(200);
    expect(res.body.message).toBe('Success');
    expect(hardRevokeSession).not.toHaveBeenCalled();
  });

  it('still succeeds when the current session lookup throws', async () => {
    (Session.findOne as any).mockRejectedValue(new Error('db down'));

    const res = await request(app).delete('/logout');

    expect(res.status).toBe(200);
    expect(res.body.message).toBe('Success');
    expect(hardRevokeSession).not.toHaveBeenCalled();
  });

  it('rejects logout when the access token carries no session id', async () => {
    const res = buildRes();

    await logoutCurrentSession(buildReq({ user: { id: 'user-1' }, sessionId: undefined }), res);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'unauthorized' });
    expect(hardRevokeSession).not.toHaveBeenCalled();
  });
});

describe('DELETE /logout/all', () => {
  it('logs out all user sessions', async () => {
    const sessions = [{ id: 'session-1' }, { id: 'session-2' }];
    (Session.findAll as any).mockResolvedValue(sessions);

    const res = await request(app).delete('/logout/all');

    expect(res.status).toBe(200);
    expect(res.body.message).toBe('Success');
    expect(Session.findAll).toHaveBeenCalledWith({
      where: { userId: expect.any(String), revokedAt: null },
    });
    expect(hardRevokeSession).toHaveBeenCalledTimes(2);
  });

  it('still succeeds when revoking all sessions throws', async () => {
    (Session.findAll as any).mockRejectedValue(new Error('db down'));

    const res = await request(app).delete('/logout/all');

    expect(res.status).toBe(200);
    expect(res.body.message).toBe('Success');
  });
});

describe('POST /refresh', () => {
  it('rejects missing token', async () => {
    const res = await request(app).post('/refresh');

    expect(res.status).toBe(401);
  });

  it('rejects invalid session', async () => {
    (findRefreshSessionByToken as any).mockResolvedValue(null);

    const res = await request(app).post('/refresh').set('Authorization', 'Bearer refresh-token');

    expect(res.status).toBe(401);
  });

  it('refreshes session successfully', async () => {
    const session = {
      id: 'session-1',
      refreshTokenHash: 'hash',
      replacedBySessionId: null,
      revokedAt: null,
      userId: 'user-1',
      infraId: 'app',
      mode: 'server',
      userAgent: 'agent',
      save: vi.fn(),
    };

    (findRefreshSessionByToken as any).mockResolvedValue(session);

    (User.findByPk as any).mockResolvedValue(buildUser());

    (Session.create as any).mockResolvedValue({ id: 'new-session' });

    (signAccessToken as any).mockResolvedValue('access');
    (generateRefreshToken as any).mockReturnValue('refresh');
    (hashRefreshToken as any).mockResolvedValue('hash');
    (createRefreshTokenLookup as any).mockReturnValue('refresh-lookup');

    (getSystemConfig as any).mockResolvedValue({
      access_token_ttl: '15m',
      refresh_token_ttl: '1h',
    });

    const res = await request(app).post('/refresh').set('Authorization', 'Bearer refresh-token');

    expect(res.status).toBe(200);
    expect(signAccessToken).toHaveBeenCalledWith(
      'new-session',
      expect.any(String),
      expect.any(Array),
      undefined,
    );
    expect(Session.create).toHaveBeenCalledWith(
      expect.objectContaining({ refreshTokenLookup: 'refresh-lookup' }),
    );
    expect(res.body.refreshToken).toBe('refresh');
  });

  it('rejects a jwt-shaped bearer token with no session', async () => {
    (findRefreshSessionByToken as any).mockResolvedValue(null);

    const res = await request(app).post('/refresh').set('Authorization', 'Bearer aaa.bbb.ccc');

    expect(res.status).toBe(401);
    expect(res.body.error).toBe('invalid_refresh_token');
  });

  it('detects refresh token reuse for an already revoked session', async () => {
    const session = {
      id: 'session-1',
      replacedBySessionId: null,
      revokedAt: new Date(),
      userId: 'user-1',
      save: vi.fn(),
    };

    (findRefreshSessionByToken as any).mockResolvedValue(session);

    const res = await request(app).post('/refresh').set('Authorization', 'Bearer refresh-token');

    expect(res.status).toBe(401);
    expect(res.body.error).toBe('refresh_token_reused');
    expect(revokeSessionChain).toHaveBeenCalledWith(session);
  });

  it('detects refresh token reuse and revokes the chain', async () => {
    const session = {
      id: 'session-1',
      replacedBySessionId: 'session-2',
      revokedAt: null,
      userId: 'user-1',
      save: vi.fn(),
    };

    (findRefreshSessionByToken as any).mockResolvedValue(session);

    const res = await request(app).post('/refresh').set('Authorization', 'Bearer refresh-token');

    expect(res.status).toBe(401);
    expect(res.body.error).toBe('refresh_token_reused');
    expect(revokeSessionChain).toHaveBeenCalledWith(session);
  });

  it('revokes the session when the refresh user no longer exists', async () => {
    const session = {
      id: 'session-1',
      replacedBySessionId: null,
      revokedAt: null,
      userId: 'user-1',
      save: vi.fn(),
    };

    (findRefreshSessionByToken as any).mockResolvedValue(session);
    (User.findByPk as any).mockResolvedValue(null);

    const res = await request(app).post('/refresh').set('Authorization', 'Bearer refresh-token');

    expect(res.status).toBe(401);
    expect(res.body.error).toBe('invalid_session');
    expect(hardRevokeSession).toHaveBeenCalledWith(session, 'user_not_found');
  });

  it('returns 500 when a new access token cannot be signed', async () => {
    const session = {
      id: 'session-1',
      replacedBySessionId: null,
      revokedAt: null,
      userId: 'user-1',
      infraId: 'app',
      mode: 'server',
      userAgent: 'agent',
      organizationId: undefined,
      save: vi.fn(),
    };

    (findRefreshSessionByToken as any).mockResolvedValue(session);
    (User.findByPk as any).mockResolvedValue(buildUser());
    (Session.create as any).mockResolvedValue({ id: 'new-session' });
    (generateRefreshToken as any).mockReturnValue('refresh');
    (hashRefreshToken as any).mockResolvedValue('hash');
    (createRefreshTokenLookup as any).mockReturnValue('refresh-lookup');
    (signAccessToken as any).mockResolvedValue(null);
    (getSystemConfig as any).mockResolvedValue({
      access_token_ttl: '15m',
      refresh_token_ttl: '1h',
    });

    const res = await request(app).post('/refresh').set('Authorization', 'Bearer refresh-token');

    expect(res.status).toBe(500);
    expect(res.body.error).toBe('Failed to refresh session');
  });

  it('refreshes with default TTLs when none are configured', async () => {
    const session = {
      id: 'session-1',
      replacedBySessionId: null,
      revokedAt: null,
      userId: 'user-1',
      infraId: 'app',
      mode: 'server',
      userAgent: 'agent',
      organizationId: undefined,
      save: vi.fn(),
    };

    (findRefreshSessionByToken as any).mockResolvedValue(session);
    (User.findByPk as any).mockResolvedValue(buildUser());
    (Session.create as any).mockResolvedValue({ id: 'new-session' });
    (signAccessToken as any).mockResolvedValue('access');
    (generateRefreshToken as any).mockReturnValue('refresh');
    (hashRefreshToken as any).mockResolvedValue('hash');
    (createRefreshTokenLookup as any).mockReturnValue('refresh-lookup');
    (getSystemConfig as any).mockResolvedValue({});

    const res = await request(app).post('/refresh').set('Authorization', 'Bearer refresh-token');

    expect(res.status).toBe(200);
    expect(res.body.ttl).toBe(900);
    expect(res.body.refreshTtl).toBe(3600);
  });
});
