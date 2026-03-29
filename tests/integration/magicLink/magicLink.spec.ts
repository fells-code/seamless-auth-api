import request from 'supertest';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { Application } from 'express';

import { User } from '../../../src/models/users.js';
import { MagicLinkToken } from '../../../src/models/magicLinks.js';
import { Session } from '../../../src/models/sessions.js';

import { createApp } from '../../../src/app.js';
import { getSystemConfig } from '../../../src/config/getSystemConfig.js';
import { generateRefreshToken, hashRefreshToken, signAccessToken } from '../../../src/lib/token.js';

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
  });

  it('rejects used token', async () => {
    (MagicLinkToken.findOne as any).mockResolvedValue(buildMagicLink({ used_at: new Date() }));

    const res = await request(app).get('/magic-link/verify/token');

    expect(res.status).toBe(400);
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
});

describe('GET /magic-link/check', () => {
  it('returns 400 when user not found', async () => {
    (User.findOne as any).mockResolvedValue(null);

    const res = await request(app).get('/magic-link/check');

    expect(res.status).toBe(400);
  });

  it('returns 500 when no token found', async () => {
    (User.findOne as any).mockResolvedValue({ id: 'user-1', email: 'test@example.com' });
    (MagicLinkToken.findOne as any).mockResolvedValue(null);

    const res = await request(app).get('/magic-link/check');

    expect(res.status).toBe(500);
  });

  it('returns 204 when not yet verified', async () => {
    (User.findOne as any).mockResolvedValue({ id: 'user-1', email: 'test@example.com' });

    (MagicLinkToken.findOne as any).mockResolvedValue(buildMagicLink({ used_at: null }));

    const res = await request(app).get('/magic-link/check');

    expect(res.status).toBe(204);
  });
});

it('creates session when magic link completed', async () => {
  const user = {
    id: 'user-1',
    email: 'test@example.com',
    roles: ['user'],
    save: vi.fn(),
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
  (signAccessToken as any).mockResolvedValue('access-token');

  const res = await request(app).get('/magic-link/check');

  expect(res.status).toBe(200);
});
