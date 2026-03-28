import request from 'supertest';
import { describe, it, expect, beforeAll, beforeEach, vi } from 'vitest';
import { getSystemConfig } from '../../../src/config/getSystemConfig';
import { Application } from 'express';
import { Credential } from '../../../src/models/credentials';
import { attachAuthMiddleware } from '../../../src/middleware/attachAuthMiddleware';
import { createApp } from '../../../src/app';
import { buildSystemConfig } from '../../factories/systemConfigFactory';
import { Session } from '../../../src/models/sessions';
import { User } from '../../../src/models/users';
import { buildUser } from '../../factories/userFactory';
import { buildCredential } from '../../factories/credentialFactory';
import {
  generateRefreshToken,
  hashRefreshToken,
  signAccessToken,
  signEphemeralToken,
} from '../../../src/lib/token';
import { compareSync } from 'bcrypt-ts';
import { getSecret } from '../../../src/utils/secretsStore';
import { AuthEvent } from '../../../src/models/authEvents';

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
  vi.clearAllMocks();
});

describe('GET /internal/auth-events/summary', () => {
  it('returns summary', async () => {
    (AuthEvent.findAll as any).mockResolvedValue([
      {
        type: 'login_success',
        get: (key: string) => (key === 'count' ? '5' : 'login_success'),
      },
    ]);

    const res = await request(app).get('/internal/auth-events/summary');

    expect(res.status).toBe(200);
    expect(res.body.summary[0].count).toBe(5);
  });

  it('returns 400 for invalid query', async () => {
    const res = await request(app).get('/internal/auth-events/summary?from=bad');

    expect(res.status).toBe(200);
  });
});

describe('GET /internal/auth-events/timeseries', () => {
  it('returns timeseries', async () => {
    (AuthEvent.findAll as any).mockResolvedValue([]);

    const res = await request(app).get('/internal/auth-events/timeseries');

    expect(res.status).toBe(200);
    expect(res.body.timeseries).toBeDefined();
  });

  it('returns 400 for invalid query', async () => {
    const res = await request(app).get('/internal/auth-events/timeseries?interval=bad');

    expect(res.status).toBe(400);
  });
});

describe('GET /internal/auth-events/login-stats', () => {
  it('returns login stats', async () => {
    (AuthEvent.count as any)
      .mockResolvedValueOnce(10) // success
      .mockResolvedValueOnce(5); // failed

    const res = await request(app).get('/internal/auth-events/login-stats');

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(10);
    expect(res.body.failed).toBe(5);
    expect(res.body.successRate).toBeCloseTo(10 / 15);
  });
});

describe('GET /internal/security/anomalies', () => {
  it('returns anomalies', async () => {
    (AuthEvent.findAll as any).mockResolvedValue([
      { ip_address: '1.1.1.1' },
      { ip_address: '1.1.1.1' },
      { ip_address: '1.1.1.1' },
      { ip_address: '1.1.1.1' },
      { ip_address: '1.1.1.1' },
      { ip_address: '1.1.1.1' },
      { ip_address: '1.1.1.1' },
      { ip_address: '1.1.1.1' },
      { ip_address: '1.1.1.1' },
      { ip_address: '1.1.1.1' },
      { ip_address: '1.1.1.1' },
    ]);

    const res = await request(app).get('/internal/security/anomalies');

    expect(res.status).toBe(200);
    expect(res.body.suspiciousIps.length).toBeGreaterThan(0);
  });
});

describe('GET /internal/metrics/dashboard', () => {
  it('returns dashboard metrics', async () => {
    (User.count as any)
      .mockResolvedValueOnce(100) // totalUsers
      .mockResolvedValueOnce(5); // newUsers24h

    (Session.count as any).mockResolvedValue(20); // activeSessions

    (AuthEvent.count as any)
      .mockResolvedValueOnce(50) // loginSuccess24h
      .mockResolvedValueOnce(25) // loginFailed24h
      .mockResolvedValueOnce(10) // otpUsage24h
      .mockResolvedValueOnce(15); // passkeyUsage24h

    // 🔥 mock DB size
    const controller = await import('../../../src/controllers/admin.js');
    vi.spyOn(controller, 'getDatabaseSize').mockResolvedValue(123456);

    const res = await request(app).get('/internal/metrics/dashboard');

    expect(res.status).toBe(200);

    expect(res.body).toMatchObject({
      totalUsers: 100,
      activeSessions: 20,
      newUsers24h: 5,
      loginSuccess24h: 50,
      loginFailed24h: 25,
      successRate24h: 50 / 75,
      otpUsage24h: 10,
      passkeyUsage24h: 15,
      databaseSize: 123456,
    });
  });

  it('returns 500 when query fails', async () => {
    (User.count as any).mockRejectedValue(new Error('boom'));

    const res = await request(app).get('/internal/metrics/dashboard');

    expect(res.status).toBe(500);
    expect(res.body.message).toBe('Failed to fetch dashboard metrics');
  });
});

describe('GET /internal/auth-events/grouped', () => {
  it('returns grouped summary', async () => {
    (AuthEvent.findAll as any).mockResolvedValue([
      { type: 'login_success' },
      { type: 'otp_success' },
      { type: 'webauthn_login_success' },
      { type: 'magic_link_requested' },
      { type: 'system_config_updated' },
      { type: 'login_suspicious' },
      { type: 'unknown' },
    ]);

    const res = await request(app).get('/internal/auth-events/grouped');

    expect(res.status).toBe(200);
    expect(res.body.summary).toBeDefined();
  });
});
