import { mintInternalServiceToken } from '../../factories/serviceTokenFactory.js';
import request from 'supertest';
import { describe, it, expect, beforeAll, beforeEach, vi } from 'vitest';
import { createApp } from '../../../src/app';
import { Application } from 'express';

import { buildUser } from '../../factories/userFactory.js';
import { generateEmailOTP, generatePhoneOTP, verifyPhoneOTP } from '../../../src/utils/otp.js';

vi.mock('../../../src/models/users.js', () => ({
  User: {
    findOne: vi.fn(),
    create: vi.fn(),
  },
}));

vi.mock('../../../src/utils/otp.js', () => ({
  generateEmailOTP: vi.fn(),
  generatePhoneOTP: vi.fn(),
  verifyPhoneOTP: vi.fn(),
}));

vi.mock('../../../src/config/getSystemConfig.js', () => ({
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

import { User } from '../../../src/models/users.js';
import { signEphemeralToken } from '../../../src/lib/token.js';
import { getSystemConfig } from '../../../src/config/getSystemConfig.js';
import { buildRegistrationRequest } from '../../factories/requestFactory.js';
import {
  register,
  registerPhone,
  verifyRegisteredPhone,
} from '../../../src/controllers/registration.js';

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

beforeAll(async () => {
  app = await createApp();
});

beforeEach(() => {
  vi.clearAllMocks();

  (getSystemConfig as any).mockResolvedValue({
    default_roles: ['user'],
  });

  (signEphemeralToken as any).mockResolvedValue('mock-token');
  (generateEmailOTP as any).mockResolvedValue('EMAILME');
  (generatePhoneOTP as any).mockResolvedValue(123456);
  (verifyPhoneOTP as any).mockResolvedValue({ user: buildUser(), verified: true });
});

describe('POST /registration/register', () => {
  it('creates a new email-only user and sends an email OTP', async () => {
    (User.findOne as any).mockResolvedValue(null);

    const user = buildUser({ phone: null });

    (User.create as any).mockResolvedValue(user);

    const res = await request(app).post('/registration/register').send(buildRegistrationRequest());

    expect(res.status).toBe(200);
    expect(res.body.message).toBe('Success');

    expect(User.create).toHaveBeenCalled();
    expect(signEphemeralToken).toHaveBeenCalledWith(user.id);
    expect(generateEmailOTP).toHaveBeenCalledWith(user, { sendMessage: true });
    expect(generatePhoneOTP).not.toHaveBeenCalled();
  });

  it('handles existing user by sending an email OTP', async () => {
    const user = buildUser();

    (User.findOne as any).mockResolvedValue(user);

    const res = await request(app).post('/registration/register').send(buildRegistrationRequest());

    expect(res.status).toBe(200);

    expect(User.create).not.toHaveBeenCalled();
    expect(signEphemeralToken).toHaveBeenCalledWith(user.id);
    expect(generateEmailOTP).toHaveBeenCalledWith(user, { sendMessage: true });
    expect(generatePhoneOTP).not.toHaveBeenCalled();
  });

  it('returns external email OTP delivery payload', async () => {
    (User.findOne as any).mockResolvedValue(null);

    const user = buildUser({ phone: null });

    (User.create as any).mockResolvedValue(user);

    const res = await request(app)
      .post('/registration/register')
      .set('x-seamless-auth-delivery-mode', 'external')
      .set('x-seamless-service-token', await mintInternalServiceToken())
      .send(buildRegistrationRequest());

    expect(res.status).toBe(200);
    expect(res.body.delivery).toEqual({
      kind: 'otp_email',
      to: user.email,
      token: 'EMAILME',
    });
    expect(generateEmailOTP).toHaveBeenCalledWith(user, { sendMessage: false });
  });

  it('treats null phone as omitted', async () => {
    (User.findOne as any).mockResolvedValue(null);

    const user = buildUser({ phone: null });

    (User.create as any).mockResolvedValue(user);

    const res = await request(app)
      .post('/registration/register')
      .send(buildRegistrationRequest({ phone: null }));

    expect(res.status).toBe(200);
    expect(User.create).toHaveBeenCalledWith(expect.objectContaining({ phone: null }));
    expect(generateEmailOTP).toHaveBeenCalled();
  });

  it('rejects when email belongs to one user and phone is new', async () => {
    (User.findOne as any)
      .mockResolvedValueOnce(buildUser({ email: 'test@example.com', phone: '+14155552671' }))
      .mockResolvedValueOnce(null);

    const res = await request(app)
      .post('/registration/register')
      .send(buildRegistrationRequest({ phone: '+14155550000' }));

    expect(res.status).toBe(409);
    expect(res.body.error).toBe('Registration conflict');
    expect(User.create).not.toHaveBeenCalled();
    expect(signEphemeralToken).not.toHaveBeenCalled();
    expect(generatePhoneOTP).not.toHaveBeenCalled();
    expect(generateEmailOTP).not.toHaveBeenCalled();
  });

  it('rejects when phone belongs to one user and email is new', async () => {
    (User.findOne as any)
      .mockResolvedValueOnce(null)
      .mockResolvedValueOnce(buildUser({ email: 'test@example.com', phone: '+14155552671' }));

    const res = await request(app)
      .post('/registration/register')
      .send(buildRegistrationRequest({ email: 'other@example.com', phone: '+14155552671' }));

    expect(res.status).toBe(409);
    expect(res.body.error).toBe('Registration conflict');
    expect(User.create).not.toHaveBeenCalled();
    expect(signEphemeralToken).not.toHaveBeenCalled();
    expect(generatePhoneOTP).not.toHaveBeenCalled();
    expect(generateEmailOTP).not.toHaveBeenCalled();
  });

  it('rejects when email and phone belong to different existing users', async () => {
    (User.findOne as any)
      .mockResolvedValueOnce(buildUser({ id: 'user-1', email: 'test@example.com' }))
      .mockResolvedValueOnce(buildUser({ id: 'user-2', phone: '+14155552671' }));

    const res = await request(app)
      .post('/registration/register')
      .send(buildRegistrationRequest({ phone: '+14155552671' }));

    expect(res.status).toBe(409);
    expect(res.body.error).toBe('Registration conflict');
    expect(User.create).not.toHaveBeenCalled();
    expect(signEphemeralToken).not.toHaveBeenCalled();
    expect(generatePhoneOTP).not.toHaveBeenCalled();
    expect(generateEmailOTP).not.toHaveBeenCalled();
  });

  it('fails without email', async () => {
    const res = await request(app).post('/registration/register').send({ phone: '+15555555555' });

    expect(res.status).toBe(400);
  });

  it('fails invalid email', async () => {
    const res = await request(app)
      .post('/registration/register')
      .send(buildRegistrationRequest({ email: 'bad' }));

    expect(res.status).toBe(400);
  });

  it('rejects an invalid optional phone number', async () => {
    const res = await request(app)
      .post('/registration/register')
      .send(buildRegistrationRequest({ phone: 'not-a-phone' }));

    expect(res.status).toBe(400);
    expect(User.findOne).not.toHaveBeenCalled();
  });

  it('stores a bootstrap token hash for an existing user', async () => {
    const user = buildUser({ phone: null });
    (User.findOne as any).mockResolvedValue(user);

    const res = await request(app)
      .post('/registration/register')
      .send(buildRegistrationRequest({ bootstrapToken: 'bootstrap-token-value' }));

    expect(res.status).toBe(200);
    expect(user.update).toHaveBeenCalledWith(
      expect.objectContaining({
        challengeContext: expect.objectContaining({
          bootstrapInviteTokenHash: expect.any(String),
        }),
      }),
    );
  });

  it('stores a bootstrap token hash for a new user', async () => {
    (User.findOne as any).mockResolvedValue(null);
    const user = buildUser({ phone: null });
    (User.create as any).mockResolvedValue(user);

    const res = await request(app)
      .post('/registration/register')
      .send(buildRegistrationRequest({ bootstrapToken: 'bootstrap-token-value' }));

    expect(res.status).toBe(200);
    expect(User.create).toHaveBeenCalledWith(
      expect.objectContaining({
        challengeContext: expect.objectContaining({
          bootstrapInviteTokenHash: expect.any(String),
        }),
      }),
    );
  });

  it('handles unexpected errors', async () => {
    (User.findOne as any).mockRejectedValue(new Error('boom'));

    const res = await request(app).post('/registration/register').send(buildRegistrationRequest());

    expect(res.status).toBe(500);
  });

  it('handles non-error rejections', async () => {
    (User.findOne as any).mockRejectedValue('boom');

    const res = await request(app).post('/registration/register').send(buildRegistrationRequest());

    expect(res.status).toBe(500);
    expect(res.body.error).toBe('Internal server error');
  });

  it('creates a new user when both a fresh email and phone are supplied', async () => {
    (User.findOne as any).mockResolvedValue(null);
    const user = buildUser();
    (User.create as any).mockResolvedValue(user);

    const res = await request(app)
      .post('/registration/register')
      .send(buildRegistrationRequest({ phone: '+14155550000' }));

    expect(res.status).toBe(200);
    expect(User.create).toHaveBeenCalledWith(expect.objectContaining({ phone: '+14155550000' }));
  });

  it('rejects an email that fails semantic validation', async () => {
    const res = buildRes();

    await register(buildReq({ body: { email: 'still-not-valid' } }), res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ error: 'Invalid data.', message: 'Invalid data.' });
    expect(User.create).not.toHaveBeenCalled();
  });
});

describe('POST /registration/phone', () => {
  it('registers a phone number and sends a phone OTP', async () => {
    (User.findOne as any).mockResolvedValue(null);

    const res = await request(app)
      .post('/registration/phone')
      .set('x-seamless-auth-delivery-mode', 'external')
      .set('x-seamless-service-token', await mintInternalServiceToken())
      .send({ phone: '+14155550000' });

    expect(res.status).toBe(200);
    expect(res.body.phone).toBe('+14155550000');
    expect(res.body.delivery).toEqual({
      kind: 'otp_sms',
      to: '+14155550000',
      token: 123456,
    });
    expect(generatePhoneOTP).toHaveBeenCalled();
  });

  it('rejects an in-use phone number', async () => {
    (User.findOne as any).mockResolvedValue(buildUser({ id: 'other-user' }));

    const res = await request(app).post('/registration/phone').send({ phone: '+14155550000' });

    expect(res.status).toBe(409);
    expect(generatePhoneOTP).not.toHaveBeenCalled();
  });

  it('rejects an invalid phone number', async () => {
    const res = await request(app).post('/registration/phone').send({ phone: 'not-a-phone' });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('Invalid data');
    expect(generatePhoneOTP).not.toHaveBeenCalled();
  });

  it('skips OTP delivery when the phone is unchanged and already verified', async () => {
    (User.findOne as any).mockResolvedValue(null);

    const res = await request(app).post('/registration/phone').send({ phone: '+14155552671' });

    expect(res.status).toBe(200);
    expect(res.body.phone).toBe('+14155552671');
    expect(res.body.delivery).toBeUndefined();
    expect(generatePhoneOTP).not.toHaveBeenCalled();
  });

  it('returns 500 when the phone lookup throws', async () => {
    (User.findOne as any).mockRejectedValue(new Error('db down'));

    const res = await request(app).post('/registration/phone').send({ phone: '+14155550000' });

    expect(res.status).toBe(500);
    expect(res.body.error).toBe('Internal server error');
  });

  it('rejects phone registration without an authenticated user', async () => {
    const res = buildRes();

    await registerPhone(buildReq({ user: undefined, body: { phone: '+14155550000' } }), res);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'Unauthorized' });
  });

  it('rejects phone registration when no phone value is present', async () => {
    const res = buildRes();

    await registerPhone(buildReq({ user: buildUser(), body: {} }), res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ error: 'Invalid data' });
  });
});

describe('POST /registration/phone/verify', () => {
  it('verifies a registered phone number', async () => {
    const res = await request(app)
      .post('/registration/phone/verify')
      .send({ verificationToken: '123456' });

    expect(res.status).toBe(200);
    expect(verifyPhoneOTP).toHaveBeenCalled();
  });

  it('rejects an incorrect verification token', async () => {
    (verifyPhoneOTP as any).mockResolvedValue({ verified: false });

    const res = await request(app)
      .post('/registration/phone/verify')
      .send({ verificationToken: '000000' });

    expect(res.status).toBe(401);
    expect(res.body.error).toBe('Not allowed');
  });

  it('returns 500 when verification throws', async () => {
    (verifyPhoneOTP as any).mockRejectedValue(new Error('boom'));

    const res = await request(app)
      .post('/registration/phone/verify')
      .send({ verificationToken: '123456' });

    expect(res.status).toBe(500);
    expect(res.body.error).toBe('Internal server error');
  });

  it('rejects verification without an authenticated user', async () => {
    const res = buildRes();

    await verifyRegisteredPhone(
      buildReq({ user: undefined, body: { verificationToken: 'x' } }),
      res,
    );

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'Unauthorized' });
  });

  it('rejects verification when phone verification data is missing', async () => {
    const res = buildRes();
    const user = buildUser({
      phone: null,
      phoneVerificationToken: null,
      phoneVerificationTokenExpiry: null,
    });

    await verifyRegisteredPhone(buildReq({ user, body: { verificationToken: '123456' } }), res);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'Failed to verify OTP' });
  });

  it('rejects verification when the token is missing from the request', async () => {
    const res = buildRes();
    const user = buildUser({
      phone: '+14155552671',
      phoneVerificationToken: '123456',
      phoneVerificationTokenExpiry: new Date(Date.now() + 100000),
    });

    await verifyRegisteredPhone(buildReq({ user, body: {} }), res);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'Not allowed' });
  });
});
