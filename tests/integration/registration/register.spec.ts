import request from 'supertest';
import { describe, it, expect, beforeAll, beforeEach, vi } from 'vitest';
import { createApp } from '../../../src/app';
import { Application } from 'express';

import { buildUser } from '../../factories/users/userFactory.js';

// 🔥 mocks
vi.mock('../../../src/models/users.js', () => ({
  User: {
    findOne: vi.fn(),
    create: vi.fn(),
  },
}));

vi.mock('../../../src/models/authEvents.js', () => ({
  AuthEvent: {
    create: vi.fn(),
  },
}));

vi.mock('../../../src/lib/token.js', () => ({
  signEphemeralToken: vi.fn(),
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
  },
}));

vi.mock('../../../src/lib/cookie.js', () => ({
  setAuthCookies: vi.fn(),
}));

// imports after mocks
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
});

describe('POST /registration/register', () => {
  // ✅ Happy path - new user
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

  // ✅ Existing user
  it('handles existing user', async () => {
    const user = buildUser();

    (User.findOne as any).mockResolvedValue(user);

    const res = await request(app).post('/registration/register').send(buildRegistrationRequest());

    expect(res.status).toBe(200);

    expect(User.create).not.toHaveBeenCalled();
    expect(signEphemeralToken).toHaveBeenCalledWith(user.id);
  });

  // ❌ Missing email
  it('fails without email', async () => {
    const res = await request(app).post('/registration/register').send({ phone: '+15555555555' });

    expect(res.status).toBe(400);
  });

  // ❌ Missing phone
  it('fails without phone', async () => {
    const res = await request(app)
      .post('/registration/register')
      .send({ email: 'test@example.com' });

    expect(res.status).toBe(400);
  });

  // ❌ Invalid email
  it('fails invalid email', async () => {
    const res = await request(app)
      .post('/registration/register')
      .send(buildRegistrationRequest({ email: 'bad' }));

    expect(res.status).toBe(400);
  });

  // 💥 Error case
  it('handles unexpected errors', async () => {
    (User.findOne as any).mockRejectedValue(new Error('boom'));

    const res = await request(app).post('/registration/register').send(buildRegistrationRequest());

    expect(res.status).toBe(500);
  });
});
