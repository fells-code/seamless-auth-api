import { mintInternalServiceToken } from '../../factories/serviceTokenFactory.js';
import request from 'supertest';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { Application } from 'express';

import { User } from '../../../src/models/users.js';
import { Credential } from '../../../src/models/credentials.js';
import { MagicLinkToken } from '../../../src/models/magicLinks.js';
import { Session } from '../../../src/models/sessions.js';

import { createApp } from '../../../src/app.js';
import { getSystemConfig } from '../../../src/config/getSystemConfig.js';
import {
  pollMagicLinkConfirmation,
  requestMagicLink,
  confirmMagicLink,
  verifyMagicLink,
} from '../../../src/controllers/magicLinks.js';
import {
  createRefreshTokenLookup,
  generateRefreshToken,
  signAccessToken,
} from '../../../src/lib/token.js';
import { AuthEventService } from '../../../src/services/authEventService.js';
import { verifyJwtWithKid } from '../../../src/services/sessionService.js';
import { sendMagicLinkEmail } from '../../../src/services/messagingService.js';
import { hashDeviceFingerprint } from '../../../src/utils/utils.js';

let app: Application;

function buildMagicLink(overrides: any = {}) {
  return {
    id: 'link-1',
    user_id: 'user-1',
    token_hash: 'hash',
    used_at: null,
    expires_at: new Date(Date.now() + 100000),
    ip_hash: 'ip',
    user_agent_hash: 'ua',
    attempt_id: 'attempt-1',
    requested_device_class: 'macos',
    created_at: new Date('2026-10-16T12:00:00.000Z'),
    ...overrides,
  };
}

function directRes() {
  const res: any = {};
  res.status = vi.fn().mockReturnValue(res);
  res.json = vi.fn().mockReturnValue(res);
  res.end = vi.fn().mockReturnValue(res);
  return res;
}

function directVerifyReq(opts: {
  ip: string;
  userAgent: string;
  bearer?: string;
  trusted?: boolean;
}) {
  return {
    params: { token: 'token' },
    ip: opts.ip,
    ...(opts.trusted === false ? {} : { trustedClientIp: opts.ip }),
    headers: {
      'user-agent': opts.userAgent,
      ...(opts.bearer ? { authorization: `Bearer ${opts.bearer}` } : {}),
    },
    get: () => undefined,
  } as any;
}

beforeAll(async () => {
  app = await createApp();
});

beforeEach(() => {
  vi.clearAllMocks();
  (verifyJwtWithKid as any).mockReset();

  (User.findOne as any).mockResolvedValue({
    id: 'user-1',
    email: 'test@example.com',
  });

  (getSystemConfig as any).mockResolvedValue({
    available_roles: ['user', 'admin'],
    default_roles: ['user'],
    access_token_ttl: '15m',
    refresh_token_ttl: '1h',
    session_idle_ttl: '8h',
    origins: ['http://localhost:5174'],
    login_methods: ['passkey', 'magic_link'],
    passkey_login_fallback_enabled: true,
  });
});

describe('GET /magic-link', () => {
  it('returns success message even if user not found', async () => {
    (User.findOne as any).mockResolvedValue(null);

    const res = await request(app).get('/magic-link');

    expect(res.status).toBe(200);
    expect(res.body.message).toContain('If an account exists');
  });

  it('creates magic link when user exists', async () => {
    (User.findOne as any).mockResolvedValue({
      id: 'user-1',
      email: 'test@example.com',
    });

    (MagicLinkToken.update as any).mockResolvedValue([1]);
    (MagicLinkToken.create as any).mockResolvedValue({});

    const res = await request(app).get('/magic-link');

    expect(res.status).toBe(200);
    expect(MagicLinkToken.create).toHaveBeenCalled();
  });

  it('returns external magic-link delivery payload without direct email delivery', async () => {
    (MagicLinkToken.update as any).mockResolvedValue([1]);
    (MagicLinkToken.create as any).mockResolvedValue({ id: 'link-1' });

    const res = await request(app)
      .get('/magic-link')
      .set('x-seamless-auth-delivery-mode', 'external')
      .set('x-seamless-service-token', await mintInternalServiceToken());

    expect(res.status).toBe(200);
    expect(sendMagicLinkEmail).not.toHaveBeenCalled();
    expect(res.body.delivery).toEqual({
      kind: 'magic_link_email',
      to: 'test@example.com',
      token: expect.any(String),
      magicLinkUrl: expect.stringContaining('http://localhost:5174/verify-magiclink?token='),
    });
    expect(res.body.delivery.magicLinkUrl).toContain(res.body.delivery.token);
  });

  it('builds the magic link from frontend_url when set, regardless of origins order', async () => {
    (getSystemConfig as any).mockResolvedValue({
      available_roles: ['user', 'admin'],
      default_roles: ['user'],
      access_token_ttl: '15m',
      refresh_token_ttl: '1h',
      session_idle_ttl: '8h',
      origins: ['http://localhost:3000', 'http://localhost:5001'],
      frontend_url: 'http://localhost:5001',
      login_methods: ['passkey', 'magic_link'],
      passkey_login_fallback_enabled: true,
    });
    (MagicLinkToken.update as any).mockResolvedValue([1]);
    (MagicLinkToken.create as any).mockResolvedValue({ id: 'link-1' });

    const res = await request(app)
      .get('/magic-link')
      .set('x-seamless-auth-delivery-mode', 'external')
      .set('x-seamless-service-token', await mintInternalServiceToken());

    expect(res.status).toBe(200);
    expect(res.body.delivery.magicLinkUrl).toContain(
      'http://localhost:5001/verify-magiclink?token=',
    );
  });

  it('sends the link to a requested target whose origin is configured', async () => {
    (MagicLinkToken.update as any).mockResolvedValue([1]);
    (MagicLinkToken.create as any).mockResolvedValue({ id: 'link-1' });

    const res = await request(app)
      .get('/magic-link')
      .query({ redirectUri: 'http://localhost:5174/app/magic' })
      .set('x-seamless-auth-delivery-mode', 'external')
      .set('x-seamless-service-token', await mintInternalServiceToken());

    expect(res.status).toBe(200);
    expect(res.body.delivery.magicLinkUrl).toContain('http://localhost:5174/app/magic?token=');
    expect(res.body.delivery.magicLinkUrl).toContain(res.body.delivery.token);
  });

  it('refuses a requested target outside the configured origins', async () => {
    (MagicLinkToken.update as any).mockResolvedValue([1]);
    (MagicLinkToken.create as any).mockResolvedValue({ id: 'link-1' });

    const res = await request(app)
      .get('/magic-link')
      .query({ redirectUri: 'https://evil.example/steal' });

    expect(res.status).toBe(400);
    expect(res.body).toEqual({ error: 'Redirect URI is not allowed' });
    expect(sendMagicLinkEmail).not.toHaveBeenCalled();
  });

  it('rejects a redirectUri that is not a URL before it reaches the controller', async () => {
    const res = await request(app).get('/magic-link').query({ redirectUri: 'not-a-url' });

    expect(res.status).toBe(400);
    expect(sendMagicLinkEmail).not.toHaveBeenCalled();
  });

  it('returns an error when direct magic-link delivery fails', async () => {
    (MagicLinkToken.update as any).mockResolvedValue([1]);
    (MagicLinkToken.create as any).mockResolvedValue({ id: 'link-1' });
    (sendMagicLinkEmail as any).mockRejectedValue(new Error('delivery failed'));

    const res = await request(app).get('/magic-link');

    expect(res.status).toBe(500);
    expect(res.body.error).toBe('Failed to deliver magic link');
    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: 'user-1',
        type: 'magic_link_failed',
        metadata: { reason: 'Delivery failed' },
      }),
    );
  });

  it('rejects requests without identifiable device metadata', async () => {
    (User.findOne as any).mockResolvedValue({ id: 'user-1', email: 'test@example.com' });
    (hashDeviceFingerprint as any).mockReturnValueOnce({ ip_hash: null, user_agent_hash: null });

    const res = await request(app).get('/magic-link');

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('Invalid device data');
    expect(MagicLinkToken.create).not.toHaveBeenCalled();
  });

  it('refuses a magic link to a passkey holder when fallback is off', async () => {
    (getSystemConfig as any).mockResolvedValue({
      origins: ['http://localhost:5174'],
      login_methods: ['passkey', 'magic_link'],
      passkey_login_fallback_enabled: false,
    });
    (Credential.count as any).mockResolvedValue(1);

    const requested = await request(app).get('/magic-link');
    const polled = await request(app).get('/magic-link/check');

    expect(requested.status).toBe(403);
    expect(requested.body.error).toBe('login_method_disabled');
    expect(polled.status).toBe(403);
    expect(MagicLinkToken.create).not.toHaveBeenCalled();
  });

  it('refuses magic links in phishing-resistant-only mode', async () => {
    (getSystemConfig as any).mockResolvedValue({
      origins: ['http://localhost:5174'],
      login_methods: ['passkey', 'magic_link'],
      passkey_login_fallback_enabled: true,
      phishing_resistant_only: true,
    });

    const res = await request(app).get('/magic-link');

    expect(res.status).toBe(403);
    expect(MagicLinkToken.create).not.toHaveBeenCalled();
  });

  it('rejects magic link requests when the method is disabled', async () => {
    (getSystemConfig as any).mockResolvedValue({
      origins: ['http://localhost:5174'],
      login_methods: ['passkey'],
      passkey_login_fallback_enabled: true,
    });

    const res = await request(app).get('/magic-link');

    expect(res.status).toBe(403);
    expect(res.body.error).toBe('login_method_disabled');
    expect(MagicLinkToken.create).not.toHaveBeenCalled();
  });
});

describe('GET /magic-link/verify/:token', () => {
  it('rejects missing token', async () => {
    const res = await request(app).get('/magic-link/verify/');

    expect(res.status).toBe(404); // route mismatch
  });

  it('rejects invalid token', async () => {
    (MagicLinkToken.findOne as any).mockResolvedValue(null);

    const res = await request(app).get('/magic-link/verify/bad');

    expect(res.status).toBe(400);
    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'magic_link_failed',
        metadata: { reason: 'Invalid verification token' },
      }),
    );
  });

  it('rejects used token', async () => {
    (MagicLinkToken.findOne as any).mockResolvedValue(buildMagicLink({ used_at: new Date() }));

    const res = await request(app).get('/magic-link/verify/token');

    expect(res.status).toBe(400);
    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: 'user-1',
        type: 'magic_link_failed',
        metadata: { reason: 'Token already used' },
      }),
    );
  });

  it('rejects expired token', async () => {
    (MagicLinkToken.findOne as any).mockResolvedValue(
      buildMagicLink({ expires_at: new Date(Date.now() - 1000) }),
    );

    const res = await request(app).get('/magic-link/verify/token');

    expect(res.status).toBe(400);
  });

  it('accepts a valid token opened by the requesting attempt', async () => {
    (MagicLinkToken.findOne as any).mockResolvedValue(buildMagicLink());
    (MagicLinkToken.update as any).mockResolvedValue([1]);
    (verifyJwtWithKid as any).mockResolvedValue({ jti: 'attempt-1' });

    const res = await request(app)
      .get('/magic-link/verify/token')
      .set('Authorization', 'Bearer pre-auth');

    expect(res.status).toBe(200);
    expect(verifyJwtWithKid).toHaveBeenCalledWith('pre-auth', 'ephemeral');
    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'magic_link_success',
        metadata: { reason: 'Magic link token consumed', confirmation: 'same_device' },
      }),
    );
  });

  it('asks for confirmation when opened on another device, without consuming the link', async () => {
    // Anyone can request a link for someone else's address from their own machine, and
    // the session goes to the requesting device. So a link opened anywhere else must
    // not complete without the person who opened it approving.
    (MagicLinkToken.findOne as any).mockResolvedValue(
      buildMagicLink({ ip_hash: 'a-different-device', user_agent_hash: 'another-ua' }),
    );

    const res = await request(app).get('/magic-link/verify/token');

    expect(res.status).toBe(409);
    expect(res.body).toEqual({
      error: 'confirmation_required',
      message: expect.any(String),
      requestedFrom: { deviceClass: 'macos', requestedAt: '2026-10-16T12:00:00.000Z' },
    });
    expect(MagicLinkToken.update).not.toHaveBeenCalled();
    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({ userId: 'user-1', type: 'magic_link_confirmation_required' }),
    );
  });

  it('asks for confirmation when the bearer belongs to another attempt, even on a matching fingerprint', async () => {
    // hashDeviceFingerprint is mocked to the hashes buildMagicLink uses, so this link
    // matches the request's fingerprint.
    (MagicLinkToken.findOne as any).mockResolvedValue(buildMagicLink());
    (verifyJwtWithKid as any).mockResolvedValue({ jti: 'attempt-2' });
    const res = directRes();

    await verifyMagicLink(
      directVerifyReq({ ip: '203.0.113.7', userAgent: 'same-browser', bearer: 'other' }),
      res,
    );

    expect(res.status).toHaveBeenCalledWith(409);
    expect(MagicLinkToken.update).not.toHaveBeenCalled();
  });

  it('falls back to the IP and user agent when no valid bearer is forwarded', async () => {
    // hashDeviceFingerprint is mocked to the hashes buildMagicLink uses, so this link
    // matches the request's fingerprint.
    (MagicLinkToken.findOne as any).mockResolvedValue(buildMagicLink());
    (MagicLinkToken.update as any).mockResolvedValue([1]);
    (verifyJwtWithKid as any).mockResolvedValue(null);
    const res = directRes();

    await verifyMagicLink(
      directVerifyReq({ ip: '203.0.113.7', userAgent: 'same-browser', bearer: 'expired' }),
      res,
    );

    expect(res.status).toHaveBeenCalledWith(200);
    expect(MagicLinkToken.update).toHaveBeenCalled();
  });

  it('treats a bearer that fails to verify like no bearer at all', async () => {
    (MagicLinkToken.findOne as any).mockResolvedValue(
      buildMagicLink({ ip_hash: 'a-different-device', user_agent_hash: 'another-ua' }),
    );
    (verifyJwtWithKid as any).mockRejectedValue(new Error('bad signature'));
    const res = directRes();

    await verifyMagicLink(
      directVerifyReq({ ip: '203.0.113.7', userAgent: 'other-browser', bearer: 'forged' }),
      res,
    );

    expect(res.status).toHaveBeenCalledWith(409);
    expect(MagicLinkToken.update).not.toHaveBeenCalled();
  });

  // Behind an adapter that does not forward the client context, every request carries
  // the adapter's own address and user agent, so a matching fingerprint proves nothing.
  it('asks for confirmation on a matching fingerprint no adapter vouched for', async () => {
    (MagicLinkToken.findOne as any).mockResolvedValue(buildMagicLink());
    const res = directRes();

    await verifyMagicLink(
      directVerifyReq({ ip: '10.0.0.5', userAgent: 'node', trusted: false }),
      res,
    );

    expect(res.status).toHaveBeenCalledWith(409);
    expect(MagicLinkToken.update).not.toHaveBeenCalled();
  });

  it('refuses a link created before attempt binding', async () => {
    (MagicLinkToken.findOne as any).mockResolvedValue(buildMagicLink({ attempt_id: null }));

    const res = await request(app).get('/magic-link/verify/token');

    expect(res.status).toBe(400);
    expect(MagicLinkToken.update).not.toHaveBeenCalled();
  });

  it('rejects verification when the token param is empty (direct invocation)', async () => {
    const res: any = {};
    res.status = vi.fn().mockReturnValue(res);
    res.json = vi.fn().mockReturnValue(res);

    await verifyMagicLink({ params: {} } as any, res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ error: 'Missing verification token' });
  });

  it('rejects token verification when magic links are disabled', async () => {
    (getSystemConfig as any).mockResolvedValue({
      login_methods: ['passkey'],
      passkey_login_fallback_enabled: true,
    });

    const res = await request(app).get('/magic-link/verify/token');

    expect(res.status).toBe(403);
    expect(res.body.error).toBe('login_method_disabled');
    expect(MagicLinkToken.findOne).not.toHaveBeenCalled();
  });

  it('returns 500 when the token cannot be atomically consumed', async () => {
    (MagicLinkToken.findOne as any).mockResolvedValue(buildMagicLink());
    (MagicLinkToken.update as any).mockResolvedValue([0]);
    (verifyJwtWithKid as any).mockResolvedValue({ jti: 'attempt-1' });

    const res = await request(app)
      .get('/magic-link/verify/token')
      .set('Authorization', 'Bearer pre-auth');

    expect(res.status).toBe(500);
    expect(res.body.error).toBe('Failed to use token');
    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'magic_link_failed',
        metadata: { reason: 'Failed to consume token' },
      }),
    );
  });
});

describe('POST /magic-link/verify/:token/confirm', () => {
  it('consumes a link opened on another device once the person approves', async () => {
    (MagicLinkToken.findOne as any).mockResolvedValue(
      buildMagicLink({ ip_hash: 'a-different-device', user_agent_hash: 'another-ua' }),
    );
    (MagicLinkToken.update as any).mockResolvedValue([1]);

    const res = await request(app).post('/magic-link/verify/token/confirm');

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ message: 'Success' });
    expect(MagicLinkToken.update).toHaveBeenCalledWith(
      { used_at: expect.any(Date) },
      { where: { id: 'link-1', used_at: null } },
    );
    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'magic_link_success',
        metadata: { reason: 'Magic link token consumed', confirmation: 'confirmed' },
      }),
    );
  });

  it('refuses a link that is already used', async () => {
    (MagicLinkToken.findOne as any).mockResolvedValue(buildMagicLink({ used_at: new Date() }));

    const res = await request(app).post('/magic-link/verify/token/confirm');

    expect(res.status).toBe(400);
    expect(MagicLinkToken.update).not.toHaveBeenCalled();
  });

  it('refuses an expired link', async () => {
    (MagicLinkToken.findOne as any).mockResolvedValue(
      buildMagicLink({ expires_at: new Date(Date.now() - 1000) }),
    );

    const res = await request(app).post('/magic-link/verify/token/confirm');

    expect(res.status).toBe(400);
  });

  it('rejects a missing token (direct invocation)', async () => {
    const res = directRes();

    await confirmMagicLink({ params: {} } as any, res);

    expect(res.status).toHaveBeenCalledWith(400);
  });
});

describe('GET /magic-link/check', () => {
  it('returns 400 when user not found', async () => {
    (User.findOne as any).mockResolvedValue(null);

    const res = await request(app).get('/magic-link/check');

    expect(res.status).toBe(400);
  });

  it('returns 204 when no active token is found', async () => {
    (User.findOne as any).mockResolvedValue({ id: 'user-1', email: 'test@example.com' });
    (MagicLinkToken.findOne as any).mockResolvedValue(null);

    const res = await request(app).get('/magic-link/check');

    expect(res.status).toBe(204);
    expect(AuthEventService.log).not.toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'magic_link_failed',
        metadata: { reason: 'No active token found while polling' },
      }),
    );
  });

  it('returns 204 when not yet verified', async () => {
    (User.findOne as any).mockResolvedValue({ id: 'user-1', email: 'test@example.com' });

    (MagicLinkToken.findOne as any).mockResolvedValue(buildMagicLink({ used_at: null }));

    const res = await request(app).get('/magic-link/check');

    expect(res.status).toBe(204);
  });

  it('returns 403 when the polling fingerprint does not match the pending link', async () => {
    (User.findOne as any).mockResolvedValue({ id: 'user-1', email: 'test@example.com' });
    (MagicLinkToken.findOne as any).mockResolvedValue(
      buildMagicLink({ ip_hash: 'different-ip-hash', used_at: null }),
    );

    const res = await request(app).get('/magic-link/check');

    expect(res.status).toBe(403);
    expect(res.body.error).toBe('Invalid request');
    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: 'user-1',
        type: 'magic_link_failed',
        metadata: { reason: 'Polling device IP mismatch' },
      }),
    );
    expect(Session.create).not.toHaveBeenCalled();
  });

  it('returns 403 when the polling user-agent does not match the pending link', async () => {
    (User.findOne as any).mockResolvedValue({ id: 'user-1', email: 'test@example.com' });
    (MagicLinkToken.findOne as any).mockResolvedValue(
      buildMagicLink({ user_agent_hash: 'different-ua-hash', used_at: null }),
    );

    const res = await request(app).get('/magic-link/check');

    expect(res.status).toBe(403);
    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: 'user-1',
        type: 'magic_link_failed',
        metadata: { reason: 'Polling device user agent mismatch' },
      }),
    );
    expect(Session.create).not.toHaveBeenCalled();
  });

  it('rejects polling when magic links are disabled', async () => {
    (getSystemConfig as any).mockResolvedValue({
      login_methods: ['passkey'],
      passkey_login_fallback_enabled: true,
    });

    const res = await request(app).get('/magic-link/check');

    expect(res.status).toBe(403);
    expect(res.body.error).toBe('login_method_disabled');
    expect(User.findOne).not.toHaveBeenCalled();
  });

  it('polls with 204 and an empty body while waiting (regression: previously 500)', async () => {
    // The exact bug that created this branch: polling before confirmation returned 500,
    // breaking the CLI starter sign-in. It must return 204 (No Content), never 500.
    (User.findOne as any).mockResolvedValue({ id: 'user-1', email: 'test@example.com' });
    (MagicLinkToken.findOne as any).mockResolvedValue(buildMagicLink({ used_at: null }));

    const res = await request(app).get('/magic-link/check');

    expect(res.status).toBe(204);
    expect(res.status).not.toBe(500);
    expect(res.text).toBe('');
  });
});

it('creates session when magic link completed', async () => {
  const user = {
    id: 'user-1',
    email: 'test@example.com',
    roles: ['user'],
    save: vi.fn(),
    update: vi.fn(),
  };

  (User.findOne as any).mockResolvedValue(user);

  (MagicLinkToken.findOne as any).mockResolvedValue(
    buildMagicLink({
      used_at: new Date(),
      expires_at: new Date(Date.now() + 100000),
      ip_hash: 'ip',
      user_agent_hash: 'ua',
    }),
  );

  (MagicLinkToken.update as any).mockResolvedValue([1]);
  (Session.create as any).mockResolvedValue({ id: 'session-1' });

  (generateRefreshToken as any).mockReturnValue('refresh-token');
  (createRefreshTokenLookup as any).mockReturnValue('refresh-lookup');
  (signAccessToken as any).mockResolvedValue('access-token');

  const res = await request(app).get('/magic-link/check');

  expect(res.status).toBe(200);
  expect(res.body).toEqual(
    expect.objectContaining({
      message: 'Success',
      token: 'access-token',
      refreshToken: 'refresh-token',
      sub: 'user-1',
      roles: ['user'],
      ttl: 900,
      refreshTtl: 3600,
    }),
  );
});

describe('magic link attempt binding and redemption', () => {
  const completedUser = () => ({
    id: 'user-1',
    email: 'test@example.com',
    roles: ['user'],
    save: vi.fn(),
    update: vi.fn(),
  });

  it('stores the requesting attempt on the link', async () => {
    (sendMagicLinkEmail as any).mockResolvedValue(undefined);
    (MagicLinkToken.update as any).mockResolvedValue([1]);
    (MagicLinkToken.create as any).mockResolvedValue({ id: 'link-1' });

    const res = await request(app).get('/magic-link');

    expect(res.status).toBe(200);
    expect(MagicLinkToken.create).toHaveBeenCalledWith(
      expect.objectContaining({ attempt_id: 'attempt-1' }),
    );
  });

  function mockConfirmedLink() {
    (MagicLinkToken.findOne as any).mockResolvedValue(
      buildMagicLink({
        used_at: new Date(),
        expires_at: new Date(Date.now() + 100000),
        ip_hash: 'ip',
        user_agent_hash: 'ua',
      }),
    );
    (MagicLinkToken.update as any).mockResolvedValue([1]);
    (Session.create as any).mockResolvedValue({ id: 'session-1' });
    (generateRefreshToken as any).mockReturnValue('refresh-token');
    (createRefreshTokenLookup as any).mockReturnValue('refresh-lookup');
    (signAccessToken as any).mockResolvedValue('access-token');
  }

  it('claims an unverified account and drops a phone another attempt verified', async () => {
    const user = {
      ...completedUser(),
      verified: false,
      emailVerified: false,
      phone: '+15550100',
      phoneVerified: true,
      phoneVerifiedAttemptId: 'attempt-other',
    };
    (User.findOne as any).mockResolvedValue(user);
    mockConfirmedLink();

    const res = await request(app).get('/magic-link/check');

    expect(res.status).toBe(200);
    expect(user).toEqual(
      expect.objectContaining({
        verified: true,
        emailVerified: true,
        phone: null,
        phoneVerified: false,
        phoneVerifiedAttemptId: null,
      }),
    );
    expect(user.save).toHaveBeenCalled();
  });

  it('keeps a phone the same attempt verified', async () => {
    const user = {
      ...completedUser(),
      verified: false,
      emailVerified: false,
      phone: '+15550100',
      phoneVerified: true,
      phoneVerifiedAttemptId: 'attempt-1',
    };
    (User.findOne as any).mockResolvedValue(user);
    mockConfirmedLink();

    const res = await request(app).get('/magic-link/check');

    expect(res.status).toBe(200);
    expect(user).toEqual(
      expect.objectContaining({ verified: true, phone: '+15550100', phoneVerified: true }),
    );
  });

  it('leaves an already verified account as it is', async () => {
    const user = {
      ...completedUser(),
      verified: true,
      emailVerified: true,
      phone: '+15550100',
      phoneVerified: true,
      phoneVerifiedAttemptId: null,
    };
    (User.findOne as any).mockResolvedValue(user);
    mockConfirmedLink();

    const res = await request(app).get('/magic-link/check');

    expect(res.status).toBe(200);
    expect(user).toEqual(expect.objectContaining({ phone: '+15550100', phoneVerified: true }));
  });

  it('looks the link up by the polling attempt, not only by user', async () => {
    (MagicLinkToken.findOne as any).mockResolvedValue(null);

    const res = await request(app).get('/magic-link/check');

    expect(res.status).toBe(204);
    expect(MagicLinkToken.findOne).toHaveBeenCalledWith({
      where: expect.objectContaining({ user_id: 'user-1', attempt_id: 'attempt-1' }),
    });
  });

  it('issues the session once and answers later checks without one', async () => {
    (User.findOne as any).mockResolvedValue(completedUser());
    (MagicLinkToken.findOne as any).mockResolvedValue(buildMagicLink({ used_at: new Date() }));
    (Session.create as any).mockResolvedValue({ id: 'session-1' });
    (generateRefreshToken as any).mockReturnValue('refresh-token');
    (createRefreshTokenLookup as any).mockReturnValue('refresh-lookup');
    (signAccessToken as any).mockResolvedValue('access-token');

    (MagicLinkToken.update as any).mockResolvedValueOnce([1]);
    const first = await request(app).get('/magic-link/check');

    (MagicLinkToken.update as any).mockResolvedValueOnce([0]);
    const second = await request(app).get('/magic-link/check');

    expect(first.status).toBe(200);
    expect(first.body.token).toBe('access-token');
    expect(second.status).toBe(200);
    expect(second.body).toEqual({ message: 'Success' });
    expect(Session.create).toHaveBeenCalledTimes(1);
    expect(MagicLinkToken.update).toHaveBeenCalledWith(
      { redeemed_at: expect.any(Date) },
      { where: { id: 'link-1', redeemed_at: null } },
    );
  });
});

describe('magic link without an attempt id', () => {
  const directReq = () =>
    ({
      user: { id: 'user-1', email: 'test@example.com' },
      ip: '127.0.0.1',
      headers: { 'user-agent': 'test-agent' },
      query: {},
      get: () => undefined,
    }) as any;

  it('refuses to create a link that no poll could collect', async () => {
    const res = directRes();

    await requestMagicLink(directReq(), res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'magic_link_failed',
        metadata: { reason: 'Ephemeral token has no attempt id' },
      }),
    );
    expect(MagicLinkToken.create).not.toHaveBeenCalled();
  });

  it('refuses to poll without an attempt to match', async () => {
    const res = directRes();

    await pollMagicLinkConfirmation(directReq(), res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'magic_link_failed',
        metadata: { reason: 'Ephemeral token has no attempt id' },
      }),
    );
    expect(MagicLinkToken.findOne).not.toHaveBeenCalled();
    expect(Session.create).not.toHaveBeenCalled();
  });
});

describe('magic link full sign-in sequence (regression)', () => {
  it('request -> poll(waiting) -> verify -> poll issues a session', async () => {
    const user = {
      id: 'user-1',
      email: 'test@example.com',
      roles: ['user'],
      save: vi.fn(),
      update: vi.fn(),
    };
    (User.findOne as any).mockResolvedValue(user);
    // clearAllMocks (beforeEach) clears calls but not implementations, so reset the
    // delivery mock another test may have left rejecting.
    (sendMagicLinkEmail as any).mockResolvedValue(undefined);

    // 1) Request the link
    (MagicLinkToken.update as any).mockResolvedValue([1]);
    (MagicLinkToken.create as any).mockResolvedValue({ id: 'link-1' });
    const requestRes = await request(app).get('/magic-link');
    expect(requestRes.status).toBe(200);

    // 2) Poll before the link is verified -> 204 (still waiting), not 500
    (MagicLinkToken.findOne as any).mockResolvedValue(buildMagicLink({ used_at: null }));
    const pendingPoll = await request(app).get('/magic-link/check');
    expect(pendingPoll.status).toBe(204);

    // 3) Verify the token (marks it used)
    (MagicLinkToken.findOne as any).mockResolvedValue(buildMagicLink({ used_at: null }));
    (MagicLinkToken.update as any).mockResolvedValue([1]);
    (verifyJwtWithKid as any).mockResolvedValue({ jti: 'attempt-1' });
    const verifyRes = await request(app)
      .get('/magic-link/verify/token')
      .set('Authorization', 'Bearer pre-auth');
    expect(verifyRes.status).toBe(200);

    // 4) Poll after verification -> session issued
    (MagicLinkToken.findOne as any).mockResolvedValue(buildMagicLink({ used_at: new Date() }));
    (Session.create as any).mockResolvedValue({ id: 'session-1' });
    (generateRefreshToken as any).mockReturnValue('refresh-token');
    (createRefreshTokenLookup as any).mockReturnValue('refresh-lookup');
    (signAccessToken as any).mockResolvedValue('access-token');

    const completedPoll = await request(app).get('/magic-link/check');
    expect(completedPoll.status).toBe(200);
    expect(completedPoll.body).toEqual(
      expect.objectContaining({
        message: 'Success',
        token: 'access-token',
        refreshToken: 'refresh-token',
        sub: 'user-1',
      }),
    );
  });
});
