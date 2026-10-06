import request from 'supertest';
import { Application } from 'express';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import { createApp } from '../../../src/app';
import { getSystemConfig } from '../../../src/config/getSystemConfig.js';
import { getSequelize } from '../../../src/models/index.js';
import { User } from '../../../src/models/users.js';
import { AuthEventService } from '../../../src/services/authEventService.js';
import { sendEnrollmentInviteEmail } from '../../../src/services/messagingService.js';
import { buildSystemConfig } from '../../factories/systemConfigFactory.js';

vi.mock('../../../src/models/index.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/models/index.js')>()),
  getSequelize: vi.fn(),
}));

const query = vi.fn();
const userId = 'b1a7c2f4-0b1e-4c4f-9e1a-2f6d3c4b5a69';
let app: Application;

beforeAll(async () => {
  app = await createApp();
});

beforeEach(() => {
  vi.clearAllMocks();
  query.mockReset();
  vi.mocked(getSequelize).mockReturnValue({ query } as never);
  (getSystemConfig as any).mockResolvedValue(
    buildSystemConfig({
      login_methods: ['passkey', 'email_otp'],
      origins: ['http://localhost:5173'],
      frontend_url: 'http://localhost:5173',
    }),
  );
  (User.update as any).mockResolvedValue([1]);
});

describe('GET /admin/enrollment', () => {
  it('reports enrollment progress for an organization', async () => {
    query.mockImplementation(async (sql: string) =>
      sql.includes('FILTER')
        ? [{ total: 3, none: 2, one: 1, twoOrMore: 0, filtered: 2 }]
        : [
            {
              id: userId,
              email: 'ada@example.com',
              imported: true,
              credentialCount: 0,
              lastLogin: null,
              enrollmentInvitedAt: null,
            },
          ],
    );

    const res = await request(app).get(
      `/admin/enrollment?organizationId=${userId}&status=none&imported=true`,
    );

    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      summary: { total: 3, none: 2, one: 1, twoOrMore: 0 },
      users: [
        {
          id: userId,
          email: 'ada@example.com',
          imported: true,
          credentialCount: 0,
          status: 'none',
          lastLogin: null,
          enrollmentInvitedAt: null,
        },
      ],
      total: 2,
    });
  });

  it('rejects an unknown status', async () => {
    const res = await request(app).get('/admin/enrollment?status=all');

    expect(res.status).toBe(400);
    expect(query).not.toHaveBeenCalled();
  });
});

describe('POST /admin/enrollment/invites', () => {
  beforeEach(() => {
    query.mockResolvedValue([
      {
        id: userId,
        email: 'ada@example.com',
        imported: true,
        credentialCount: 0,
        lastLogin: null,
        enrollmentInvitedAt: null,
      },
    ]);
  });

  it('emails the invite and records it against the acting admin', async () => {
    const res = await request(app)
      .post('/admin/enrollment/invites')
      .send({ userIds: [userId] });

    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      sent: 1,
      skipped: 0,
      results: [{ userId, status: 'sent' }],
    });
    expect(sendEnrollmentInviteEmail).toHaveBeenCalledWith(
      'ada@example.com',
      'http://localhost:5173/login',
    );
    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({
        userId,
        type: 'admin_enrollment_invite_sent',
        actorUserId: expect.any(String),
        metadata: { external: false },
      }),
    );
  });

  // The invite carries no secret, so external delivery does not need the service
  // token that guards codes and magic links.
  it('returns the delivery in external mode without sending it', async () => {
    const res = await request(app)
      .post('/admin/enrollment/invites')
      .set('x-seamless-auth-delivery-mode', 'external')
      .send({ userIds: [userId] });

    expect(res.status).toBe(200);
    expect(res.body.results[0].delivery).toEqual({
      kind: 'enrollment_invite_email',
      to: 'ada@example.com',
      signInUrl: 'http://localhost:5173/login',
    });
    expect(sendEnrollmentInviteEmail).not.toHaveBeenCalled();
  });

  it('answers 409 when the tenant only allows passkeys', async () => {
    (getSystemConfig as any).mockResolvedValue(buildSystemConfig({ login_methods: ['passkey'] }));

    const res = await request(app)
      .post('/admin/enrollment/invites')
      .send({ userIds: [userId] });

    expect(res.status).toBe(409);
    expect(sendEnrollmentInviteEmail).not.toHaveBeenCalled();
  });

  it('requires exactly one target', async () => {
    const res = await request(app).post('/admin/enrollment/invites').send({});

    expect(res.status).toBe(400);
  });

  it('answers 500 when something unexpected fails', async () => {
    query.mockRejectedValue(new Error('database down'));

    const res = await request(app)
      .post('/admin/enrollment/invites')
      .send({ userIds: [userId] });

    expect(res.status).toBe(500);
  });

  it('invites an organization and records it on each invite', async () => {
    query.mockImplementation(async (sql: string) =>
      sql.includes('COUNT(*)::int AS count')
        ? [{ count: 1 }]
        : [
            {
              id: userId,
              email: 'ada@example.com',
              imported: true,
              credentialCount: 0,
              lastLogin: null,
              enrollmentInvitedAt: null,
            },
          ],
    );

    const res = await request(app)
      .post('/admin/enrollment/invites')
      .send({ organizationId: userId });

    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ sent: 1, remaining: 0 });
    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'admin_enrollment_invite_sent',
        metadata: { external: false, organizationId: userId },
      }),
    );
  });
});
