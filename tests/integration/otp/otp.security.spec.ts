import request from 'supertest';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { Application } from 'express';

import { createApp } from '../../../src/app';
import { verifyPhoneOTP, verifyEmailOTP } from '../../../src/utils/otp.js';

let app: Application;

beforeAll(async () => {
  app = await createApp();
});

beforeEach(() => {
  vi.resetModules();
  vi.clearAllMocks();
});

describe('OTP Security - Phone Verification', () => {
  it('rejects missing verification token', async () => {
    const res = await request(app)
      .post('/otp/verify-phone-otp')
      .set('Authorization', 'Bearer token')
      .send({});

    expect(res.status).toBe(400);
  });

  it('rejects invalid OTP token', async () => {
    (verifyPhoneOTP as any).mockResolvedValue({
      user: {},
      verified: false,
    });

    const res = await request(app)
      .post('/otp/verify-phone-otp')
      .set('Authorization', 'Bearer token')
      .send({ verificationToken: 'bad-token' });

    expect(res.status).toBe(401);
  });

  it('rejects expired OTP (simulated)', async () => {
    (verifyPhoneOTP as any).mockResolvedValue({
      user: {
        id: 'user-1',
        phoneVerificationToken: '123456',
        phoneVerificationTokenExpiry: new Date(Date.now() - 1000), // expired
        email: 'test@example.com',
        phone: '+14155552671',
        verified: true,
        phoneVerified: false,
        emailVerified: true,
        roles: ['user'],
        update: vi.fn(),
      },
      verified: false,
    });

    const res = await request(app)
      .post('/otp/verify-phone-otp')
      .set('Authorization', 'Bearer token')
      .send({ verificationToken: '123456' });

    expect(res.status).toBe(401);
  });

  it('rejects replayed OTP', async () => {
    (verifyPhoneOTP as any).mockResolvedValue({
      user: {
        id: 'user-1',
        phoneVerificationToken: '123456',
        phoneVerificationTokenExpiry: new Date(Date.now() + 100000),
        email: 'test@example.com',
        phone: '+14155552671',
        verified: true,
        phoneVerified: true, // already verified → replay
        emailVerified: true,
        roles: ['user'],
        update: vi.fn(),
      },
      verified: false,
    });

    const res = await request(app)
      .post('/otp/verify-phone-otp')
      .set('Authorization', 'Bearer token')
      .send({ verificationToken: '123456' });

    expect(res.status).toBe(401);
  });
});

describe('OTP Security - Email Verification', () => {
  it('rejects missing verification token', async () => {
    const res = await request(app)
      .post('/otp/verify-email-otp')
      .set('Authorization', 'Bearer token')
      .send({});

    expect(res.status).toBe(400);
  });

  it('rejects invalid OTP token', async () => {
    (verifyEmailOTP as any).mockResolvedValue({
      user: {},
      verified: false,
    });

    const res = await request(app)
      .post('/otp/verify-email-otp')
      .set('Authorization', 'Bearer token')
      .send({ verificationToken: 'bad' });

    expect(res.status).toBe(401);
  });

  it('rejects expired OTP', async () => {
    (verifyEmailOTP as any).mockResolvedValue({
      user: {
        id: 'user-1',
        emailVerificationToken: '123456',
        emailVerificationTokenExpiry: new Date(Date.now() - 1000),
        email: 'test@example.com',
        phone: '+14155552671',
        verified: true,
        phoneVerified: true,
        emailVerified: false,
        roles: ['user'],
        update: vi.fn(),
      },
      verified: false,
    });

    const res = await request(app)
      .post('/otp/verify-email-otp')
      .set('Authorization', 'Bearer token')
      .send({ verificationToken: '123456' });

    expect(res.status).toBe(401);
  });
});
