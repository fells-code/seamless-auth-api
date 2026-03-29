import request from 'supertest';
import { describe, it, expect, beforeAll, beforeEach, vi } from 'vitest';
import { getSystemConfig } from '../../../src/config/getSystemConfig';
import { Application } from 'express';
import { Credential } from '../../../src/models/credentials';
import { createApp } from '../../../src/app';
import { Session } from '../../../src/models/sessions';
import { User } from '../../../src/models/users';
import { buildUser } from '../../factories/userFactory';
import {
  generateRefreshToken,
  hashRefreshToken,
  signAccessToken,
  signEphemeralToken,
} from '../../../src/lib/token';
import { compareSync } from 'bcrypt-ts';
import { getSecret } from '../../../src/utils/secretsStore';

let app: Application;

vi.mock('../../../src/middleware/attachAuthMiddleware.js', () => ({
  attachAuthMiddleware: () => (req: any, _res: any, next: any) => {
    req.user = buildUser();
    req.sessionId = 'session-1';
    next();
  },
}));

beforeAll(async () => {
  app = await createApp();
});

beforeEach(() => {
  vi.resetModules();
  vi.clearAllMocks();
});

describe('POST /login', () => {
  it('rejects missing identifier', async () => {
    const res = await request(app).post('/login').send({ identifier: '' });

    expect(res.status).toBe(403);
  });

  it('rejects invalid identifier', async () => {
    const res = await request(app).post('/login').send({ identifier: 'bad' });

    expect(res.status).toBe(400);
  });

  it('rejects user not found', async () => {
    (User.findOne as any).mockResolvedValue(null);

    const res = await request(app).post('/login').send({ identifier: 'test@example.com' });

    expect(res.status).toBe(401);
  });

  it('rejects unverified user', async () => {
    (User.findOne as any).mockResolvedValue(buildUser({ verified: false }));

    const res = await request(app).post('/login').send({ identifier: 'test@example.com' });

    expect(res.status).toBe(401);
  });

  it('rejects passkey required but missing credential', async () => {
    (User.findOne as any).mockResolvedValue(buildUser());
    (Credential.findOne as any).mockResolvedValue(null);

    const res = await request(app).post('/login').send({
      identifier: 'test@example.com',
      passkeyAvailable: true,
    });

    expect(res.status).toBe(401);
  });

  it('logs in successfully', async () => {
    (User.findOne as any).mockResolvedValue(buildUser({ verified: true }));
    (Credential.findOne as any).mockResolvedValue({});

    (signEphemeralToken as any).mockResolvedValue('token');

    (getSystemConfig as any).mockResolvedValue({
      access_token_ttl: '15m',
    });

    const res = await request(app).post('/login').send({
      identifier: 'test@example.com',
    });

    expect(res.status).toBe(200);
  });
});

describe('GET /logout', () => {
  it('logs out user', async () => {
    (Session.findAll as any).mockResolvedValue([{ revokedAt: null }]);

    const res = await request(app).get('/logout');

    expect(res.status).toBe(200);
    expect(res.body.message).toBe('Success');
  });
});

describe('POST /refresh', () => {
  it('rejects missing token', async () => {
    const res = await request(app).post('/refresh');

    expect(res.status).toBe(401);
  });

  it('rejects invalid session', async () => {
    const jwt = await import('jsonwebtoken');

    (jwt.default.verify as any).mockReturnValue({
      refreshToken: 'token',
    });

    (getSecret as any).mockResolvedValue('secret');

    (Session.findAll as any).mockResolvedValue([]);

    const res = await request(app).post('/refresh').set('Authorization', 'Bearer token');

    expect(res.status).toBe(401);
  });

  it('refreshes session successfully', async () => {
    const jwt = await import('jsonwebtoken');

    (jwt.default.verify as any).mockReturnValue({
      refreshToken: 'token',
    });

    (getSecret as any).mockResolvedValue('secret');

    const session = {
      id: 'session-1',
      refreshTokenHash: 'hash',
      replacedBySessionId: null,
      revokedAt: null,
      userId: 'user-1',
      infraId: 'app',
      mode: 'web',
      userAgent: 'agent',
      save: vi.fn(),
    };

    (Session.findAll as any).mockResolvedValue([session]);

    (compareSync as any).mockReturnValue(true);

    (User.findByPk as any).mockResolvedValue(buildUser());

    (Session.create as any).mockResolvedValue({ id: 'new-session' });

    (signAccessToken as any).mockResolvedValue('access');
    (generateRefreshToken as any).mockReturnValue('refresh');
    (hashRefreshToken as any).mockResolvedValue('hash');

    (getSystemConfig as any).mockResolvedValue({
      access_token_ttl: '15m',
      refresh_token_ttl: '1h',
    });

    const res = await request(app).post('/refresh').set('Authorization', 'Bearer token');

    expect(res.status).toBe(200);
  });
});
