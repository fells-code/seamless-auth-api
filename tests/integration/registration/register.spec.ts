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

let app: Application;

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

  it('handles unexpected errors', async () => {
    (User.findOne as any).mockRejectedValue(new Error('boom'));

    const res = await request(app).post('/registration/register').send(buildRegistrationRequest());

    expect(res.status).toBe(500);
  });
});

describe('POST /registration/phone', () => {
  it('registers a phone number and sends a phone OTP', async () => {
    (User.findOne as any).mockResolvedValue(null);

    const res = await request(app)
      .post('/registration/phone')
      .set('x-seamless-auth-delivery-mode', 'external')
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
});

describe('POST /registration/phone/verify', () => {
  it('verifies a registered phone number', async () => {
    const res = await request(app)
      .post('/registration/phone/verify')
      .send({ verificationToken: '123456' });

    expect(res.status).toBe(200);
    expect(verifyPhoneOTP).toHaveBeenCalled();
  });
});
