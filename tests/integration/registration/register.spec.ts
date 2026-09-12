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

import { UniqueConstraintError } from 'sequelize';

import { AuthEventService } from '../../../src/services/authEventService.js';
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
    expect(signEphemeralToken).toHaveBeenCalledWith(user.id, expect.any(String));
    expect(generateEmailOTP).toHaveBeenCalledWith(user, { sendMessage: true });
    expect(generatePhoneOTP).not.toHaveBeenCalled();
  });

  it('handles existing user by sending an email OTP', async () => {
    const user = buildUser();

    (User.findOne as any).mockResolvedValue(user);

    const res = await request(app).post('/registration/register').send(buildRegistrationRequest());

    expect(res.status).toBe(200);

    expect(User.create).not.toHaveBeenCalled();
    expect(signEphemeralToken).toHaveBeenCalledWith(user.id, expect.any(String));
    expect(generateEmailOTP).toHaveBeenCalledWith(user, { sendMessage: true });
    expect(generatePhoneOTP).not.toHaveBeenCalled();
  });

  // The lookup and the insert are two statements, so double clicking Register has both
  // requests pass the lookup. The account exists by the time the second one is refused,
  // which is the answer the sequential duplicate already gets.
  it('continues as an existing account when the create loses the race', async () => {
    const user = buildUser({ phone: null });

    (User.findOne as any).mockResolvedValueOnce(null).mockResolvedValueOnce(user);
    (User.create as any).mockRejectedValue(
      new UniqueConstraintError({ fields: { email: user.email } }),
    );

    const res = await request(app).post('/registration/register').send(buildRegistrationRequest());

    expect(res.status).toBe(200);
    expect(res.body.sub).toBe(user.id);
    expect(signEphemeralToken).toHaveBeenCalledWith(user.id, expect.any(String));
    expect(generateEmailOTP).toHaveBeenCalledWith(user, { sendMessage: true });
    expect(AuthEventService.log).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: 'registration_failed' }),
    );
  });

  it('reports a constraint violation it cannot attribute to this address', async () => {
    (User.findOne as any).mockResolvedValue(null);
    (User.create as any).mockRejectedValue(
      new UniqueConstraintError({ fields: { phone: '+14155552671' } }),
    );

    const res = await request(app).post('/registration/register').send(buildRegistrationRequest());

    expect(res.status).toBe(500);
  });

  it('does not treat an unrelated create failure as a duplicate', async () => {
    (User.findOne as any).mockResolvedValue(null);
    (User.create as any).mockRejectedValue(new Error('connection reset'));

    const res = await request(app).post('/registration/register').send(buildRegistrationRequest());

    expect(res.status).toBe(500);
    expect(res.body.error).toBe('Internal server error');
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

  // A 409 here told an unauthenticated caller whether an email was already registered,
  // which is the enumeration oracle /login is built to avoid. Every identifier
  // combination now answers with the same 200 shape.
  it('does not reveal that the email is taken when the phone is new', async () => {
    const existing = buildUser({ email: 'test@example.com', phone: '+14155552671' });
    (User.findOne as any).mockResolvedValueOnce(existing).mockResolvedValueOnce(null);

    const res = await request(app)
      .post('/registration/register')
      .send(buildRegistrationRequest({ phone: '+14155550000' }));

    expect(res.status).toBe(200);
    expect(User.create).not.toHaveBeenCalled();
    // The account keeps the phone it already had; the requested one is not attached.
    expect(existing.update).not.toHaveBeenCalled();
    expect(generateEmailOTP).toHaveBeenCalled();
  });

  it('does not reveal that the phone is taken when the email is new', async () => {
    (User.findOne as any)
      .mockResolvedValueOnce(null)
      .mockResolvedValueOnce(buildUser({ email: 'test@example.com', phone: '+14155552671' }));
    (User.create as any).mockResolvedValue(buildUser({ phone: null }));

    const res = await request(app)
      .post('/registration/register')
      .send(buildRegistrationRequest({ email: 'other@example.com', phone: '+14155552671' }));

    expect(res.status).toBe(200);
    // Created without the phone, so a number held by another account is never taken over.
    expect(User.create).toHaveBeenCalledWith(expect.objectContaining({ phone: null }));
  });

  it('does not reveal that the identifiers belong to different accounts', async () => {
    const emailOwner = buildUser({ id: 'user-1', email: 'test@example.com' });
    (User.findOne as any)
      .mockResolvedValueOnce(emailOwner)
      .mockResolvedValueOnce(buildUser({ id: 'user-2', phone: '+14155552671' }));

    const res = await request(app)
      .post('/registration/register')
      .send(buildRegistrationRequest({ phone: '+14155552671' }));

    expect(res.status).toBe(200);
    expect(User.create).not.toHaveBeenCalled();
    // Continues as the email's owner, and the other account's phone is left alone.
    expect(emailOwner.update).not.toHaveBeenCalled();
    expect(generateEmailOTP).toHaveBeenCalledWith(emailOwner, expect.anything());
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

  describe('attempt and delivery telemetry', () => {
    it('starts one attempt and stamps it, with the address, on every row it writes', async () => {
      (User.findOne as any).mockResolvedValue(null);

      const user = buildUser({ phone: null });

      (User.create as any).mockResolvedValue(user);

      const res = await request(app)
        .post('/registration/register')
        .send(buildRegistrationRequest());

      expect(res.status).toBe(200);

      const [, attemptId] = (signEphemeralToken as any).mock.calls[0];
      const rows = (AuthEventService.log as any).mock.calls.map(([options]: [any]) => options);
      const stamped = rows.filter((row: any) =>
        ['user_created', 'otp_success', 'registration_success'].includes(row.type),
      );

      expect(stamped).toHaveLength(3);

      for (const row of stamped) {
        expect(row).toMatchObject({ userId: user.id, attemptId, subjectEmail: user.email });
      }

      expect(rows.find((row: any) => row.type === 'otp_success')).toMatchObject({
        metadata: { channel: 'email' },
      });
    });

    it('records a refused send as otp_failed before answering 500', async () => {
      const { DeliveryError } = await import('../../../src/services/deliveryError.js');

      (User.findOne as any).mockResolvedValue(null);

      const user = buildUser({ phone: null });

      (User.create as any).mockResolvedValue(user);
      (generateEmailOTP as any).mockRejectedValueOnce(
        new DeliveryError('Failed to send verification email', new Error('provider down')),
      );

      const res = await request(app)
        .post('/registration/register')
        .send(buildRegistrationRequest());

      expect(res.status).toBe(500);
      expect(AuthEventService.log).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: user.id,
          subjectEmail: user.email,
          type: 'otp_failed',
          metadata: { reason: 'Delivery failed', channel: 'email' },
        }),
      );
      expect(AuthEventService.log).not.toHaveBeenCalledWith(
        expect.objectContaining({ type: 'otp_success' }),
      );
    });
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
