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

import { generatePhoneOTP, verifyPhoneOTP } from '../../src/utils/otp.js';

import {
  findRefreshSessionByToken,
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
      .get('/otp/generate-phone-otp')
      .set('Cookie', [`seamless_ephemeral=ephemeral-token`]);

    expect(otpRes.status).toBe(200);
    expect(generatePhoneOTP).toHaveBeenCalled();

    (verifyPhoneOTP as any).mockResolvedValue({
      user: {
        id: 'user-1',
        emailVerified: true,
        phoneVerified: true,
        verified: true,
        roles: ['user'],
      },
      verified: true,
    });

    (Session.create as any).mockResolvedValue({
      id: 'session-1',
    });

    const verifyRes = await request(app)
      .post('/otp/verify-phone-otp')
      .set('Cookie', [`seamless_ephemeral=ephemeral-token`])
      .send({ verificationToken: '123456' });

    expect(verifyRes.status).toBe(200);

    (validateAccessToken as any).mockResolvedValue({
      sessionId: 'session-1',
    });

    (Session.findAll as any).mockResolvedValue([buildSession()]);
    const accessRes = await request(app)
      .get('/sessions')
      .set('Cookie', [`seamless_access=access-token`]);

    expect(accessRes.status).toBe(200);

    (validateAccessToken as any).mockResolvedValue(null);
    (findRefreshSessionByToken as any).mockResolvedValue({
      session: buildSession(),
      legacyFallbackCandidates: 0,
      usedLegacyFallback: false,
    });

    (User.findByPk as any).mockResolvedValue({
      id: 'user-1',
    });

    (Session.create as any).mockResolvedValue(buildSession({ id: 'session-2' }));

    const refreshRes = await request(app)
      .get('/sessions')
      .set('Cookie', [`seamless_refresh=refresh-token`]);

    expect(refreshRes.status).toBe(200);
  });
});
