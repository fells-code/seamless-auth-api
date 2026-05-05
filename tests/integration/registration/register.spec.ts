import request from 'supertest';
import { describe, it, expect, beforeAll, beforeEach, vi } from 'vitest';
import { createApp } from '../../../src/app';
import { Application } from 'express';

import { buildUser } from '../../factories/userFactory.js';
import { generatePhoneOTP } from '../../../src/utils/otp.js';

vi.mock('../../../src/models/users.js', () => ({
  User: {
    findOne: vi.fn(),
    create: vi.fn(),
  },
}));

vi.mock('../../../src/utils/otp.js', () => ({
  generatePhoneOTP: vi.fn(),
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
  (generatePhoneOTP as any).mockResolvedValue(123456);
});

describe('POST /registration/register', () => {
  it('creates a new user', async () => {
    (User.findOne as any).mockResolvedValue(null);

    const user = buildUser();

    (User.create as any).mockResolvedValue(user);

    const res = await request(app).post('/registration/register').send(buildRegistrationRequest());

    expect(res.status).toBe(200);
    expect(res.body.message).toBe('Success');

    expect(User.create).toHaveBeenCalled();
    expect(signEphemeralToken).toHaveBeenCalledWith(user.id);
  });

  it('handles existing user', async () => {
    const user = buildUser();

    (User.findOne as any).mockResolvedValue(user);

    const res = await request(app).post('/registration/register').send(buildRegistrationRequest());

    expect(res.status).toBe(200);

    expect(User.create).not.toHaveBeenCalled();
    expect(signEphemeralToken).toHaveBeenCalledWith(user.id);
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
  });

  it('rejects when phone belongs to one user and email is new', async () => {
    (User.findOne as any)
      .mockResolvedValueOnce(null)
      .mockResolvedValueOnce(buildUser({ email: 'test@example.com', phone: '+14155552671' }));

    const res = await request(app)
      .post('/registration/register')
      .send(buildRegistrationRequest({ email: 'other@example.com' }));

    expect(res.status).toBe(409);
    expect(res.body.error).toBe('Registration conflict');
    expect(User.create).not.toHaveBeenCalled();
    expect(signEphemeralToken).not.toHaveBeenCalled();
    expect(generatePhoneOTP).not.toHaveBeenCalled();
  });

  it('rejects when email and phone belong to different existing users', async () => {
    (User.findOne as any)
      .mockResolvedValueOnce(buildUser({ id: 'user-1', email: 'test@example.com' }))
      .mockResolvedValueOnce(buildUser({ id: 'user-2', phone: '+14155552671' }));

    const res = await request(app).post('/registration/register').send(buildRegistrationRequest());

    expect(res.status).toBe(409);
    expect(res.body.error).toBe('Registration conflict');
    expect(User.create).not.toHaveBeenCalled();
    expect(signEphemeralToken).not.toHaveBeenCalled();
    expect(generatePhoneOTP).not.toHaveBeenCalled();
  });

  it('fails without email', async () => {
    const res = await request(app).post('/registration/register').send({ phone: '+15555555555' });

    expect(res.status).toBe(400);
  });

  it('fails without phone', async () => {
    const res = await request(app)
      .post('/registration/register')
      .send({ email: 'test@example.com' });

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
