import { mintInternalServiceToken } from '../../factories/serviceTokenFactory.js';
import request from 'supertest';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { Application } from 'express';

import { User } from '../../../src/models/users.js';
import { MagicLinkToken } from '../../../src/models/magicLinks.js';
import { Session } from '../../../src/models/sessions.js';

import { createApp } from '../../../src/app.js';
import { getSystemConfig } from '../../../src/config/getSystemConfig.js';
import { verifyMagicLink } from '../../../src/controllers/magicLinks.js';
import {
  createRefreshTokenLookup,
  generateRefreshToken,
  hashRefreshToken,
  signAccessToken,
} from '../../../src/lib/token.js';
import { AuthEventService } from '../../../src/services/authEventService.js';
import { maybePromoteBootstrapAdmin } from '../../../src/services/bootstrapPromotionService.js';
import { sendMagicLinkEmail } from '../../../src/services/messagingService.js';
import { hashDeviceFingerprint } from '../../../src/utils/utils.js';

vi.mock('../../../src/services/bootstrapPromotionService.js', () => ({
  maybePromoteBootstrapAdmin: vi.fn(async () => ({
    promoted: false,
    reason: 'bootstrap_disabled',
  })),
}));

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

  it('accepts a valid token even when opened on a different device', async () => {
    // The email link may legitimately be opened on a different device than the one
    // that requested it. Device binding is enforced at the poll step, not here — so
    // verify must remain device-agnostic. Guards against re-adding a device gate here.
    (MagicLinkToken.findOne as any).mockResolvedValue(
      buildMagicLink({ ip_hash: 'a-different-device', user_agent_hash: 'another-ua' }),
    );
    (MagicLinkToken.update as any).mockResolvedValue([1]);

    const res = await request(app).get('/magic-link/verify/token');

    expect(res.status).toBe(200);
    expect(MagicLinkToken.update).toHaveBeenCalled();
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

    const res = await request(app).get('/magic-link/verify/token');

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

  it('logs when the poll promotes a bootstrap admin', async () => {
    const user = {
      id: 'user-1',
      email: 'test@example.com',
      roles: ['user'],
      save: vi.fn(),
      update: vi.fn(),
    };
    (User.findOne as any).mockResolvedValue(user);
    (MagicLinkToken.findOne as any).mockResolvedValue(
      buildMagicLink({ used_at: new Date(), expires_at: new Date(Date.now() + 100000) }),
    );
    (Session.create as any).mockResolvedValue({ id: 'session-1' });
    (generateRefreshToken as any).mockReturnValue('refresh-token');
    (hashRefreshToken as any).mockResolvedValue('hashed-refresh');
    (createRefreshTokenLookup as any).mockReturnValue('refresh-lookup');
    (signAccessToken as any).mockResolvedValue('access-token');
    (maybePromoteBootstrapAdmin as any).mockResolvedValueOnce({
      promoted: true,
      reason: 'success',
    });

    const res = await request(app).get('/magic-link/check');

    expect(res.status).toBe(200);
    expect(maybePromoteBootstrapAdmin).toHaveBeenCalledWith(
      expect.objectContaining({ completionMethod: 'magic_link_fallback' }),
    );
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
    const verifyRes = await request(app).get('/magic-link/verify/token');
    expect(verifyRes.status).toBe(200);

    // 4) Poll after verification -> session issued
    (MagicLinkToken.findOne as any).mockResolvedValue(buildMagicLink({ used_at: new Date() }));
    (Session.create as any).mockResolvedValue({ id: 'session-1' });
    (generateRefreshToken as any).mockReturnValue('refresh-token');
    (hashRefreshToken as any).mockResolvedValue('hashed-refresh');
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
