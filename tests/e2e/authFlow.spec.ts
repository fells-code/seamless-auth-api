import request from 'supertest';
import { describe, it, expect, beforeAll, beforeEach, vi } from 'vitest';
import { createApp } from '../../src/app';
import { Application } from 'express';

vi.mock('../../src/config/getSystemConfig.js', () => ({
  getSystemConfig: vi.fn(),
}));

vi.mock('../../../src/services/authEventService.js', () => ({
  AuthEventService: {
    log: vi.fn(),
    notificationSent: vi.fn(),
    refreshTokenFailed: vi.fn(),
    requestSuspicious: vi.fn(),
    requestSuspiciousContext: vi.fn(),
  },
}));

import { User } from '../../src/models/users.js';
import { Session } from '../../src/models/sessions.js';

import {
  signEphemeralToken,
  signAccessToken,
  generateRefreshToken,
  hashRefreshToken,
} from '../../src/lib/token.js';

import { generateEmailOTP, verifyEmailOTP } from '../../src/utils/otp.js';

import {
  findRefreshSessionByToken,
  validateBearerToken,
  validateAccessToken,
} from '../../src/services/sessionService.js';

import { getSystemConfig } from '../../src/config/getSystemConfig.js';

import { buildRegistrationRequest } from '../factories/requestFactory.js';
import { buildUser } from '../factories/userFactory.js';
import { buildSession } from '../factories/sessionFactory.js';

let app: Application;

beforeAll(async () => {
  app = await createApp();
});

beforeEach(() => {
  vi.clearAllMocks();

  (getSystemConfig as any).mockResolvedValue({
    default_roles: ['user'],
  });

  (signEphemeralToken as any).mockResolvedValue('ephemeral-token');
  (signAccessToken as any).mockResolvedValue('access-token');
  (generateRefreshToken as any).mockReturnValue('refresh-token');
  (hashRefreshToken as any).mockResolvedValue('hashed-refresh');
  (Session.create as any).mockResolvedValue({ id: 'session-1' });
});

describe('E2E Auth Flow', () => {
  it('completes full auth lifecycle', async () => {
    (User.findOne as any).mockResolvedValue(null);

    (User.create as any).mockResolvedValue(buildUser());

    const registerRes = await request(app)
      .post('/registration/register')
      .send(buildRegistrationRequest());

    expect(registerRes.status).toBe(200);

    const otpRes = await request(app)
      .get('/otp/generate-email-otp')
      .set('Authorization', 'Bearer ephemeral-token');

    expect(otpRes.status).toBe(200);
    expect(generateEmailOTP).toHaveBeenCalled();

    (verifyEmailOTP as any).mockResolvedValue({
      user: buildUser({
        id: 'user-1',
        emailVerified: true,
        phoneVerified: false,
        verified: true,
        roles: ['user'],
      }),
      verified: true,
    });

    (Session.create as any).mockResolvedValue({
      id: 'session-1',
    });

    const verifyRes = await request(app)
      .post('/otp/verify-email-otp')
      .set('Authorization', 'Bearer ephemeral-token')
      .send({ verificationToken: '123456' });

    expect(verifyRes.status).toBe(200);
    expect(verifyRes.body).toEqual(
      expect.objectContaining({
        message: 'Success',
        token: 'access-token',
        refreshToken: 'refresh-token',
        sub: 'user-1',
        roles: ['user'],
        ttl: 900,
        refreshTtl: 86400,
      }),
    );

    (validateAccessToken as any).mockResolvedValue({
      sessionId: 'session-1',
    });

    (Session.findAll as any).mockResolvedValue([buildSession()]);
    const accessRes = await request(app)
      .get('/sessions')
      .set('Authorization', 'Bearer access-token');

    expect(accessRes.status).toBe(200);

    (validateAccessToken as any).mockResolvedValue(null);
    (validateBearerToken as any).mockResolvedValue(null);
    (findRefreshSessionByToken as any).mockResolvedValue(buildSession());

    (User.findByPk as any).mockResolvedValue({
      id: 'user-1',
      email: 'test@example.com',
      phone: '+14155552671',
      roles: ['user'],
    });

    (Session.create as any).mockResolvedValue(buildSession({ id: 'session-2' }));

    const refreshRes = await request(app)
      .post('/refresh')
      .set('Authorization', 'Bearer refresh-token');

    expect(refreshRes.status).toBe(200);
    expect(findRefreshSessionByToken).toHaveBeenCalledWith('refresh-token', expect.any(Date));
  });
});
