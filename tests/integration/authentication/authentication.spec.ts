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
import { AuthFailure } from '../../../src/models/authFailures';
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

  it('answers an unknown identifier with a decoy pre-auth token', async () => {
    (User.findOne as any).mockResolvedValue(null);
    (signEphemeralToken as any).mockResolvedValue('token');
    (getSystemConfig as any).mockResolvedValue({ access_token_ttl: '15m' });

    const res = await request(app).post('/login').send({ identifier: 'test@example.com' });

    expect(res.status).toBe(200);
    expect(res.body.token).toBe('token');
    expect(res.body.identifierType).toBe('email');
  });

  it('answers an unverified account with a decoy pre-auth token', async () => {
    (User.findOne as any).mockResolvedValue(buildUser({ verified: false }));
    (signEphemeralToken as any).mockResolvedValue('token');
    (getSystemConfig as any).mockResolvedValue({ access_token_ttl: '15m' });

    const res = await request(app).post('/login').send({ identifier: 'test@example.com' });

    expect(res.status).toBe(200);
    expect(res.body.token).toBe('token');
  });

  it('rejects passkey required but missing credential', async () => {
    (User.findOne as any).mockResolvedValue(buildUser({ verified: true }));
    (Credential.findOne as any).mockResolvedValue(null);
    (signEphemeralToken as any).mockResolvedValue('token');
    (getSystemConfig as any).mockResolvedValue({
      access_token_ttl: '15m',
      login_methods: ['passkey'],
      passkey_login_fallback_enabled: false,
    });

    const res = await request(app).post('/login').send({
      identifier: 'test@example.com',
      passkeyAvailable: true,
    });

    // The account is real but has no usable continuation method, which used to answer
    // 401 and so separated it from an unknown identifier. Both are decoys now.
    expect(res.status).toBe(200);
    expect(res.body.loginMethods).toEqual(['passkey']);
  });

  it('does not let the request body downgrade a passkey-only policy', async () => {
    (User.findOne as any).mockResolvedValue(buildUser({ verified: true }));
    (Credential.findOne as any).mockResolvedValue({});
    (signEphemeralToken as any).mockResolvedValue('token');
    (getSystemConfig as any).mockResolvedValue({
      access_token_ttl: '15m',
      login_methods: ['passkey', 'magic_link', 'email_otp'],
      passkey_login_fallback_enabled: false,
    });

    const res = await request(app).post('/login').send({
      identifier: 'test@example.com',
      passkeyAvailable: false,
    });

    expect(res.status).toBe(200);
    expect(res.body.loginMethods).toEqual(['passkey']);
    expect(res.body.loginMethods).not.toContain('email_otp');
    expect(res.body.loginMethods).not.toContain('magic_link');
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

  it('reports a server error when the ephemeral token cannot be signed', async () => {
    (User.findOne as any).mockResolvedValue(buildUser({ verified: true }));
    (Credential.findOne as any).mockResolvedValue({});
    (signEphemeralToken as any).mockResolvedValue(null);
    (getSystemConfig as any).mockResolvedValue({ access_token_ttl: '15m' });

    const res = await request(app).post('/login').send({ identifier: 'test@example.com' });

    // A decoy cannot be signed either, so this is a fault rather than an answer about
    // the account, and both paths reach it identically.
    expect(res.status).toBe(500);
    expect(res.body).toEqual({ error: 'Server error' });
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

  it('answers identically for unknown, unverified, no-method and usable identifiers', async () => {
    // One policy for every probe. A caller cannot change the deployment's login methods
    // between requests, so varying them here would compare two different servers rather
    // than two different accounts.
    (getSystemConfig as any).mockResolvedValue({
      access_token_ttl: '15m',
      login_methods: ['passkey'],
      passkey_login_fallback_enabled: false,
    });
    (signEphemeralToken as any).mockResolvedValue('token');

    const responses: request.Response[] = [];

    // Unknown identifier.
    (User.findOne as any).mockResolvedValue(null);
    responses.push(await request(app).post('/login').send({ identifier: 'nobody@example.com' }));

    // Known but unverified.
    (User.findOne as any).mockResolvedValue(buildUser({ verified: false }));
    responses.push(
      await request(app).post('/login').send({ identifier: 'unverified@example.com' }),
    );

    // Verified, but no credential under a passkey-only policy, so no continuation method.
    (User.findOne as any).mockResolvedValue(buildUser({ verified: true }));
    (Credential.findOne as any).mockResolvedValue(null);
    responses.push(await request(app).post('/login').send({ identifier: 'nomethods@example.com' }));

    // Verified, with a passkey. The one case that is a real sign-in.
    (User.findOne as any).mockResolvedValue(buildUser({ verified: true }));
    (Credential.findOne as any).mockResolvedValue({});
    responses.push(await request(app).post('/login').send({ identifier: 'real@example.com' }));

    // `sub` and `token` differ between them exactly as they differ between two real
    // accounts, so the comparison is over everything else.
    const shapes = responses.map((res) => ({
      status: res.status,
      keys: Object.keys(res.body).sort(),
      identifierType: res.body.identifierType,
      loginMethods: res.body.loginMethods,
      ttl: res.body.ttl,
    }));

    expect(shapes[0].status).toBe(200);
    expect(shapes[1]).toEqual(shapes[0]);
    expect(shapes[2]).toEqual(shapes[0]);
    expect(shapes[3]).toEqual(shapes[0]);
  });

  it('never offers a decoy an empty method list', async () => {
    // A real account with no permitted method is itself answered as a decoy, so an
    // empty list is something only a decoy could produce. Under a passkey-only policy
    // that would be every decoy the derived shape gave no passkey to, which puts the
    // old 401 back in a different costume.
    (User.findOne as any).mockResolvedValue(null);
    (signEphemeralToken as any).mockResolvedValue('token');
    (getSystemConfig as any).mockResolvedValue({
      access_token_ttl: '15m',
      login_methods: ['passkey'],
      passkey_login_fallback_enabled: false,
    });

    for (let i = 0; i < 25; i += 1) {
      const res = await request(app)
        .post('/login')
        .send({ identifier: `nobody${i}@example.com` });

      expect(res.body.loginMethods).toEqual(['passkey']);
    }
  });

  it('gives an unknown identifier the same decoy subject every time', async () => {
    (User.findOne as any).mockResolvedValue(null);
    (signEphemeralToken as any).mockResolvedValue('token');
    (getSystemConfig as any).mockResolvedValue({ access_token_ttl: '15m' });

    const first = await request(app).post('/login').send({ identifier: 'nobody@example.com' });
    const second = await request(app).post('/login').send({ identifier: 'NOBODY@example.com' });
    const other = await request(app).post('/login').send({ identifier: 'someone@example.com' });

    // A real identifier resolves to the same row on every attempt, and to a different
    // row from anyone else's. A decoy subject that rerolled, or that collided across
    // identifiers, would be the oracle again one request later.
    expect(second.body.sub).toBe(first.body.sub);
    expect(other.body.sub).not.toBe(first.body.sub);
    expect(first.body.sub).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    );
  });

  it('rejects login for a locked account', async () => {
    (User.findOne as any).mockResolvedValue(buildUser({ verified: true }));
    (AuthFailure.count as any).mockResolvedValue(10);
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
      session_idle_ttl: '8h',
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
      session_idle_ttl: '8h',
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
    expect(res.body.refreshTtl).toBe(86400);
  });
});
