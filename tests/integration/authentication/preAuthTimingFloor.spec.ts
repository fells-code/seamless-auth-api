import { Application } from 'express';
import request from 'supertest';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import { createApp } from '../../../src/app';
import { getSystemConfig } from '../../../src/config/getSystemConfig.js';
import { decoyPrincipalForSubject, decoySubjectFor } from '../../../src/services/decoyPrincipal.js';
import { buildUser } from '../../factories/userFactory';

/**
 * A real send waits on the provider and writes rows; a decoy answers from its subject.
 * `defineRoute` holds every ephemeral route, and `/registration/register`, to the floor
 * `/login` already used, so the two cannot be told apart by when they arrive.
 */

const FLOOR_MS = 150;

const caller: { user: unknown; decoy: boolean } = { user: null, decoy: false };

vi.mock('../../../src/middleware/attachAuthMiddleware.js', async (importOriginal) => {
  const actual =
    await importOriginal<typeof import('../../../src/middleware/attachAuthMiddleware.js')>();

  return {
    ...actual,
    attachAuthMiddleware: () => (req: any, _res: any, next: any) => {
      req.user = caller.user;
      req.decoy = caller.decoy;
      req.attemptId = 'attempt-1';
      next();
    },
  };
});

vi.mock('../../../src/models/authEvents.js', () => ({
  AuthEvent: { create: vi.fn() },
}));

import { signEphemeralToken } from '../../../src/lib/token.js';
import { User } from '../../../src/models/users.js';
import { generateEmailOTP } from '../../../src/utils/otp.js';

let app: Application;

beforeAll(async () => {
  process.env.LOGIN_RESPONSE_FLOOR_MS = String(FLOOR_MS);
  app = await createApp();
});

afterAll(() => {
  process.env.LOGIN_RESPONSE_FLOOR_MS = '0';
});

beforeEach(() => {
  vi.clearAllMocks();
  (signEphemeralToken as any).mockResolvedValue('token');
  (generateEmailOTP as any).mockResolvedValue('123456');
  (getSystemConfig as any).mockResolvedValue({
    default_roles: ['user'],
    login_methods: ['passkey', 'magic_link', 'email_otp', 'phone_otp'],
    passkey_login_fallback_enabled: true,
  });
});

async function timed(send: () => request.Test) {
  const startedAt = Date.now();
  const res = await send();

  return { elapsed: Date.now() - startedAt, status: res.status };
}

describe('pre-auth response floor', () => {
  it('holds /registration/register for a fresh address', async () => {
    (User.findOne as any).mockResolvedValue(null);
    (User.create as any).mockResolvedValue(buildUser({ phone: null }));

    const { elapsed, status } = await timed(() =>
      request(app).post('/registration/register').send({ email: 'new@example.com' }),
    );

    expect(status).toBe(200);
    expect(elapsed).toBeGreaterThanOrEqual(FLOOR_MS - 5);
  });

  it('holds /registration/register for a verified account', async () => {
    (User.findOne as any).mockResolvedValue(buildUser({ verified: true }));

    const { elapsed, status } = await timed(() =>
      request(app).post('/registration/register').send({ email: 'owner@example.com' }),
    );

    expect(status).toBe(200);
    expect(elapsed).toBeGreaterThanOrEqual(FLOOR_MS - 5);
  });

  it('holds an ephemeral route for a decoy', async () => {
    caller.user = decoyPrincipalForSubject(decoySubjectFor('nobody@example.com', 'email'));
    caller.decoy = true;

    const { elapsed, status } = await timed(() => request(app).get('/otp/generate-email-otp'));

    expect(status).toBe(200);
    expect(elapsed).toBeGreaterThanOrEqual(FLOOR_MS - 5);
  });

  it('holds an ephemeral route for a real account, failures included', async () => {
    caller.user = buildUser({ verified: true });
    caller.decoy = false;

    const { elapsed, status } = await timed(() =>
      request(app).post('/otp/verify-login-email-otp').send({ verificationToken: '000000' }),
    );

    expect(status).toBe(401);
    expect(elapsed).toBeGreaterThanOrEqual(FLOOR_MS - 5);
  });
});
