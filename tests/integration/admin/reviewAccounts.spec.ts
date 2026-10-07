import { Application } from 'express';
import request from 'supertest';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import { getSequelize } from '../../../src/models/index.js';
import { ReviewAccountsResponseSchema } from '../../../src/schemas/reviewAccounts.js';
import { validateBearerToken } from '../../../src/services/sessionService.js';

// Driven through the real bearer and admin checks, which every other admin spec stubs out.
vi.unmock('../../../src/middleware/attachAuthMiddleware.js');
vi.unmock('../../../src/middleware/requireAdmin.js');

vi.mock('../../../src/models/index.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/models/index.js')>()),
  getSequelize: vi.fn(),
}));

const PATH = '/admin/review-accounts';
const query = vi.fn();
let app: Application;

function asRoles(roles: string[]) {
  vi.mocked(validateBearerToken).mockResolvedValue({
    user: { id: 'admin-1', email: 'admin@example.gov', roles },
    sessionId: 'session-1',
  } as never);
}

beforeAll(async () => {
  const { createApp } = await import('../../../src/app.js');

  app = await createApp();
});

beforeEach(() => {
  vi.clearAllMocks();
  query.mockReset();
  vi.mocked(getSequelize).mockReturnValue({ query } as never);
  vi.stubEnv('REVIEW_ACCOUNT_EMAILS', 'Review@Example.com');
  vi.stubEnv('REVIEW_ACCOUNT_CODE', 'REVUEW');
  asRoles(['admin:read']);

  query.mockResolvedValue([
    { signIns: 4, failedVerifications: 2, lastSignInAt: new Date('2026-10-01T08:00:00.000Z') },
  ]);
});

describe('GET /admin/review-accounts', () => {
  it('requires a bearer token', async () => {
    const res = await request(app).get(PATH);

    expect(res.status).toBe(401);
    expect(query).not.toHaveBeenCalled();
  });

  it('requires an admin role', async () => {
    asRoles(['user']);

    const res = await request(app).get(PATH).set('Authorization', 'Bearer token');

    expect(res.status).toBe(403);
    expect(query).not.toHaveBeenCalled();
  });

  it('validates the token as an access token', async () => {
    await request(app).get(PATH).set('Authorization', 'Bearer token');

    expect(validateBearerToken).toHaveBeenCalledWith('token', 'access');
  });

  it('reports the configuration and recent use without the code', async () => {
    const res = await request(app).get(PATH).set('Authorization', 'Bearer token');

    expect(res.status).toBe(200);
    expect(ReviewAccountsResponseSchema.safeParse(res.body).success).toBe(true);
    expect(res.body).toEqual({
      enabled: true,
      emails: ['review@example.com'],
      codeConfigured: true,
      recentSignIns: {
        days: 30,
        count: 4,
        failedVerifications: 2,
        lastSignInAt: '2026-10-01T08:00:00.000Z',
      },
    });
    expect(res.text).not.toContain('REVUEW');
  });

  it('honours the window', async () => {
    const res = await request(app).get(`${PATH}?days=7`).set('Authorization', 'Bearer token');

    expect(res.status).toBe(200);
    expect(res.body.recentSignIns.days).toBe(7);
  });

  it('reports disabled when the code is unusable', async () => {
    vi.stubEnv('REVIEW_ACCOUNT_CODE', '123456');

    const res = await request(app).get(PATH).set('Authorization', 'Bearer token');

    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ enabled: false, codeConfigured: false });
  });

  it.each(['days=0', 'days=367', 'days=1.5', 'days=abc'])('rejects %s', async (search) => {
    const res = await request(app).get(`${PATH}?${search}`).set('Authorization', 'Bearer token');

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_request');
    expect(query).not.toHaveBeenCalled();
  });

  it('answers 500 when usage cannot be read', async () => {
    query.mockRejectedValue(new Error('db down'));

    const res = await request(app).get(PATH).set('Authorization', 'Bearer token');

    expect(res.status).toBe(500);
    expect(res.body).toEqual({ error: 'Failed to read review account usage' });
  });
});
