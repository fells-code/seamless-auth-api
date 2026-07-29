import request from 'supertest';
import { describe, it, expect, beforeAll, beforeEach, vi } from 'vitest';
import { Application } from 'express';
import { createApp } from '../../../src/app';
import { Session } from '../../../src/models/sessions';
import { User } from '../../../src/models/users';
import { buildUser } from '../../factories/userFactory';
import { AuthEvent } from '../../../src/models/authEvents';
import {
  getAuthEventSummary,
  getAuthEventTimeseries,
} from '../../../src/controllers/internalMetrics.js';

let app: Application;

vi.mock('../../../src/middleware/attachAuthMiddleware.js', async (importOriginal) => {
  const actual =
    await importOriginal<typeof import('../../../src/middleware/attachAuthMiddleware.js')>();

  return {
    ...actual,
    attachAuthMiddleware: () => (req: any, _res: any, next: any) => {
      req.user = buildUser();
      req.sessionId = 'session-1';
      next();
    },
  };
});

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

    expect(res.status).toBe(400);
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
      {
        user_id: 'user_1',
        type: 'login_failed',
        ip_address: '192.168.1.10',
        user_agent: 'Mozilla/5.0 Chrome',
        metadata: { reason: 'invalid_password' },
        created_at: new Date('2026-03-29T10:00:00Z'),
      },
      {
        user_id: 'user_2',
        type: 'jwt_failed',
        ip_address: '192.168.1.11',
        user_agent: 'Mozilla/5.0 Firefox',
        metadata: { reason: 'invalid_signature' },
        created_at: new Date('2026-03-29T10:05:00Z'),
      },
      {
        user_id: null,
        type: 'suspicious_ip',
        ip_address: '10.0.0.5',
        user_agent: null,
        metadata: { flagged: true },
        created_at: new Date('2026-03-29T10:10:00Z'),
      },
      {
        user_id: 'user_3',
        type: 'otp_failed',
        ip_address: '172.16.0.3',
        user_agent: 'Safari',
        metadata: { attempts: 3 },
        created_at: new Date('2026-03-29T10:15:00Z'),
      },
      {
        user_id: 'user_4',
        type: 'refresh_token_failed',
        ip_address: '192.168.1.20',
        user_agent: 'Mozilla/5.0 Edge',
        metadata: { expired: true },
        created_at: new Date('2026-03-29T10:20:00Z'),
      },
      {
        user_id: null,
        type: 'suspicious_device',
        ip_address: '203.0.113.42',
        user_agent: 'Unknown',
        metadata: { anomaly: 'new_device' },
        created_at: new Date('2026-03-29T10:25:00Z'),
      },
      {
        user_id: 'user_5',
        type: 'webauthn_login_failed',
        ip_address: '198.51.100.8',
        user_agent: 'Mozilla/5.0 Chrome',
        metadata: { challenge_failed: true },
        created_at: new Date('2026-03-29T10:30:00Z'),
      },
    ]);

    const res = await request(app).get('/internal/security/anomalies');

    expect(res.status).toBe(200);
    expect(res.body.total).toBe(7);
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
    expect(res.body.error).toBe('Failed to fetch dashboard metrics');
  });
});

describe('GET /internal/auth-events/grouped', () => {
  const countRow = (type: string, count: string) => ({
    type,
    get: (key: string) => (key === 'count' ? count : type),
  });

  it('rolls counts up into categories and outcomes', async () => {
    (AuthEvent.findAll as any).mockResolvedValue([
      countRow('login_success', '4'),
      countRow('otp_success', '3'),
      countRow('webauthn_login_success', '2'),
      countRow('magic_link_requested', '1'),
      countRow('system_config_updated', '1'),
      countRow('login_suspicious', '5'),
      countRow('unknown', '1'),
    ]);

    const res = await request(app).get('/internal/auth-events/grouped');
    const byType = Object.fromEntries(
      res.body.summary.map((row: { type: string; count: number }) => [row.type, row.count]),
    );
    const outcomes = Object.fromEntries(
      res.body.outcomes.map((row: { type: string; count: number }) => [row.type, row.count]),
    );

    expect(res.status).toBe(200);
    expect(byType).toEqual({
      login: 4,
      otp: 3,
      webauthn: 2,
      magicLink: 1,
      system: 1,
      suspicious: 5,
      other: 1,
    });
    expect(outcomes).toEqual({ success: 9, suspicious: 5, other: 3 });
  });

  it('counts in the database rather than loading every event', async () => {
    (AuthEvent.findAll as any).mockResolvedValue([]);

    await request(app).get('/internal/auth-events/grouped');

    expect((AuthEvent.findAll as any).mock.calls[0][0].group).toEqual(['type']);
  });

  it('applies a from/to created_at filter', async () => {
    (AuthEvent.findAll as any).mockResolvedValue([]);

    const res = await request(app)
      .get('/internal/auth-events/grouped')
      .query({ from: '2026-01-01', to: '2026-02-01' });

    expect(res.status).toBe(200);
    expect((AuthEvent.findAll as any).mock.calls[0][0].where.created_at).toBeDefined();
  });

  it('returns 400 for an invalid query', async () => {
    const res = await request(app).get('/internal/auth-events/grouped?from=bad');

    expect(res.status).toBe(400);
  });

  it('returns 500 when grouping fails', async () => {
    (AuthEvent.findAll as any).mockRejectedValue(new Error('boom'));

    const res = await request(app).get('/internal/auth-events/grouped');

    expect(res.status).toBe(500);
    expect(res.body.error).toBe('Failed to group events');
  });
});

describe('GET /internal/auth-events/summary (additional branches)', () => {
  it('applies a from/to created_at filter', async () => {
    (AuthEvent.findAll as any).mockResolvedValue([]);

    const res = await request(app)
      .get('/internal/auth-events/summary')
      .query({ from: '2026-01-01', to: '2026-02-01' });

    expect(res.status).toBe(200);
    expect((AuthEvent.findAll as any).mock.calls[0][0].where.created_at).toBeDefined();
  });

  it('returns 500 when the summary query fails', async () => {
    (AuthEvent.findAll as any).mockRejectedValue(new Error('boom'));

    const res = await request(app).get('/internal/auth-events/summary');

    expect(res.status).toBe(500);
    expect(res.body.error).toBe('Failed to fetch summary');
  });
});

describe('GET /internal/auth-events/timeseries (additional branches)', () => {
  const bucketRow = (bucket: string, type: string, count: string) => ({
    get: (k: string) => (k === 'bucket' ? bucket : k === 'type' ? type : count),
  });

  it('fills daily buckets across the requested window', async () => {
    const key = '2026-01-05T00:00:00.000Z';

    (AuthEvent.findAll as any).mockResolvedValue([
      bucketRow(key, 'login_success', '5'),
      bucketRow(key, 'login_failed', '3'),
    ]);

    const res = await request(app)
      .get('/internal/auth-events/timeseries')
      .query({ interval: 'day', from: '2026-01-01', to: '2026-02-01', userId: 'user-1' });

    expect(res.status).toBe(200);
    // Jan 1 through Feb 1 inclusive, rather than a now-relative 30-day window.
    expect(res.body.timeseries).toHaveLength(32);
    expect(res.body.timeseries[0].bucket).toBe('2026-01-01T00:00:00.000Z');
    expect(res.body.timeseries.at(-1).bucket).toBe('2026-02-01T00:00:00.000Z');

    const filled = res.body.timeseries.find((b: any) => b.bucket === key);
    expect(filled).toMatchObject({ success: 5, failed: 3, total: 8, categories: { login: 8 } });
    expect((AuthEvent.findAll as any).mock.calls[0][0].where.user_id).toBe('user-1');
  });

  it('defaults to the last 24 hourly buckets when no window is given', async () => {
    (AuthEvent.findAll as any).mockResolvedValue([]);

    const res = await request(app).get('/internal/auth-events/timeseries');

    expect(res.status).toBe(200);
    expect(res.body.timeseries).toHaveLength(24);
  });

  it('counts non-login activity into categories', async () => {
    const key = '2026-01-05T00:00:00.000Z';

    (AuthEvent.findAll as any).mockResolvedValue([
      bucketRow(key, 'otp_success', '4'),
      bucketRow(key, 'webauthn_login_success', '2'),
      bucketRow(key, 'magic_link_requested', '1'),
    ]);

    const res = await request(app)
      .get('/internal/auth-events/timeseries')
      .query({ interval: 'day', from: '2026-01-05', to: '2026-01-05' });

    expect(res.status).toBe(200);
    expect(res.body.timeseries).toHaveLength(1);
    expect(res.body.timeseries[0]).toMatchObject({
      bucket: key,
      success: 0,
      failed: 0,
      total: 7,
      categories: { otp: 4, webauthn: 2, magicLink: 1 },
    });
  });

  it('returns 500 when the timeseries query fails', async () => {
    (AuthEvent.findAll as any).mockRejectedValue(new Error('boom'));

    const res = await request(app).get('/internal/auth-events/timeseries');

    expect(res.status).toBe(500);
    expect(res.body.error).toBe('Failed to fetch timeseries');
  });
});

describe('GET /internal/auth-events/login-stats (additional branches)', () => {
  it('returns 500 when the login stats query fails', async () => {
    (AuthEvent.count as any).mockRejectedValue(new Error('boom'));

    const res = await request(app).get('/internal/auth-events/login-stats');

    expect(res.status).toBe(500);
    expect(res.body.error).toBe('Failed to compute login stats');
  });

  it('reports a zero success rate when there are no logins', async () => {
    (AuthEvent.count as any).mockResolvedValueOnce(0).mockResolvedValueOnce(0);

    const res = await request(app).get('/internal/auth-events/login-stats');

    expect(res.status).toBe(200);
    expect(res.body.successRate).toBe(0);
  });
});

describe('GET /internal/security/anomalies (additional branches)', () => {
  it('returns 500 when the anomaly query fails', async () => {
    (AuthEvent.findAll as any).mockRejectedValue(new Error('boom'));

    const res = await request(app).get('/internal/security/anomalies');

    expect(res.status).toBe(500);
    expect(res.body.error).toBe('Failed to detect anomalies');
  });
});

describe('internal metrics query guards (direct invocation)', () => {
  function mockRes() {
    const res: any = {};
    res.status = vi.fn().mockReturnValue(res);
    res.json = vi.fn().mockReturnValue(res);
    return res;
  }

  it('rejects an invalid summary query', async () => {
    const res = mockRes();

    await getAuthEventSummary({ query: { from: 'not-a-date' } } as any, res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ error: 'Invalid query params' });
  });

  it('rejects an invalid timeseries query', async () => {
    const res = mockRes();

    await getAuthEventTimeseries({ query: { interval: 'decade' } } as any, res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ error: 'Invalid query params' });
  });
});

describe('GET /internal/metrics/dashboard (additional branches)', () => {
  it('reports a zero success rate when there are no logins in the window', async () => {
    (User.count as any).mockResolvedValueOnce(10).mockResolvedValueOnce(0);
    (Session.count as any).mockResolvedValue(0);
    (AuthEvent.count as any)
      .mockResolvedValueOnce(0) // loginSuccess24h
      .mockResolvedValueOnce(0) // loginFailed24h
      .mockResolvedValueOnce(0) // otpUsage24h
      .mockResolvedValueOnce(0); // passkeyUsage24h

    const controller = await import('../../../src/controllers/admin.js');
    vi.spyOn(controller, 'getDatabaseSize').mockResolvedValue(1);

    const res = await request(app).get('/internal/metrics/dashboard');

    expect(res.status).toBe(200);
    expect(res.body.successRate24h).toBe(0);
  });
});
