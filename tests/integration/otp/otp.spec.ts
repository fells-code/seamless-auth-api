import request from 'supertest';
import { describe, it, expect, beforeAll, beforeEach, vi } from 'vitest';
import { createApp } from '../../../src/app';
import { Application } from 'express';

vi.mock('../../../src/models/authEvents.js', () => ({
  AuthEvent: {
    create: vi.fn(),
  },
}));

vi.mock('../../src/utils/otp.js', () => ({
  generatePhoneOTP: vi.fn(),
  generateEmailOTP: vi.fn(),
  verifyPhoneOTP: vi.fn(),
  verifyEmailOTP: vi.fn(),
}));

vi.mock('../../../src/services/sessionIssuance.js', () => ({
  issueSessionAndRespond: vi.fn(async ({ res }) => {
    // simulate real behavior
    res.status(200).json({ message: 'Success' });
  }),
}));

import {
  generatePhoneOTP,
  generateEmailOTP,
  verifyPhoneOTP,
  verifyEmailOTP,
} from '../../../src/utils/otp.js';

import { issueSessionAndRespond } from '../../../src/services/sessionIssuance.js';

let app: Application;

beforeAll(async () => {
  app = await createApp();
});

beforeEach(() => {
  vi.resetModules();
  vi.clearAllMocks();
});

describe('OTP - Generate', () => {
  it('generates phone OTP', async () => {
    const res = await request(app).get('/otp/generate-phone-otp');

    expect(res.status).toBe(200);
    expect(generatePhoneOTP).toHaveBeenCalled();
    expect(res.body.message).toBe('success');
  });

  it('generates email OTP', async () => {
    const res = await request(app).get('/otp/generate-email-otp');

    expect(res.status).toBe(200);
    expect(generateEmailOTP).toHaveBeenCalled();
  });
});

describe('OTP - Verify Phone', () => {
  it('fails when token missing', async () => {
    const res = await request(app).post('/otp/verify-phone-otp').send({});

    expect(res.status).toBe(400);
  });

  it('fails when OTP invalid', async () => {
    (verifyPhoneOTP as any).mockResolvedValue({
      user: {},
      verified: false,
    });

    const res = await request(app)
      .post('/otp/verify-phone-otp')
      .send({ verificationToken: 'wrong' });

    expect(res.status).toBe(401);
  });

  it('succeeds when OTP valid', async () => {
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

    const res = await request(app)
      .post('/otp/verify-phone-otp')
      .send({ verificationToken: '123456' });

    expect(res.status).toBe(200);
  });
});

describe('OTP - Verify Email', () => {
  it('fails when OTP invalid', async () => {
    (verifyEmailOTP as any).mockResolvedValue({
      user: {},
      verified: false,
    });

    const res = await request(app).post('/otp/verify-email-otp').send({ verificationToken: 'bad' });

    expect(res.status).toBe(401);
  });

  it('succeeds when OTP valid', async () => {
    (verifyEmailOTP as any).mockResolvedValue({
      user: {
        id: 'user-1',
        emailVerified: true,
        phoneVerified: true,
        verified: true,
        roles: ['user'],
      },
      verified: true,
    });

    const res = await request(app)
      .post('/otp/verify-email-otp')
      .send({ verificationToken: '123456' });

    expect(issueSessionAndRespond).toHaveBeenCalledTimes(1);

    const call = (issueSessionAndRespond as any).mock.calls[0][0];

    expect(call.user.id).toBe('user-1');
    expect(call.user.roles).toContain('user');
  });
});
