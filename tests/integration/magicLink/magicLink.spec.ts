import request from 'supertest';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { Application } from 'express';

import { User } from '../../../src/models/users.js';
import { MagicLinkToken } from '../../../src/models/magicLinks.js';
import { Session } from '../../../src/models/sessions.js';

import { createApp } from '../../../src/app.js';
import { getSystemConfig } from '../../../src/config/getSystemConfig.js';
import {
  createRefreshTokenLookup,
  generateRefreshToken,
  hashRefreshToken,
  signAccessToken,
} from '../../../src/lib/token.js';
import { AuthEventService } from '../../../src/services/authEventService.js';
import { sendMagicLinkEmail } from '../../../src/services/messagingService.js';

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
    ...overrides,
  };
}

beforeAll(async () => {
  app = await createApp();
});

beforeEach(() => {
  vi.clearAllMocks();

  (User.findOne as any).mockResolvedValue({
    id: 'user-1',
    email: 'test@example.com',
  });

  (getSystemConfig as any).mockResolvedValue({
    available_roles: ['user', 'admin'],
    default_roles: ['user'],
    access_token_ttl: '15m',
    refresh_token_ttl: '1h',
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
      .set('x-seamless-auth-delivery-mode', 'external');

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

  it('accepts valid token', async () => {
    (MagicLinkToken.findOne as any).mockResolvedValue(buildMagicLink());

    (MagicLinkToken.update as any).mockResolvedValue([1]);

    const res = await request(app).get('/magic-link/verify/token');

    expect(res.status).toBe(200);
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

  (Session.create as any).mockResolvedValue({ id: 'session-1' });

  (generateRefreshToken as any).mockReturnValue('refresh-token');
  (hashRefreshToken as any).mockResolvedValue('hashed-refresh');
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
