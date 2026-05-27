import request from 'supertest';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { Application } from 'express';

import { createApp } from '../../../src/app';
import { Credential } from '../../../src/models/credentials.js';
import { User } from '../../../src/models/users.js';
import { buildUser, testGuid } from '../../factories/userFactory';
import { AuthEvent } from '../../../src/models/authEvents.js';
import { Session } from '../../../src/models/sessions.js';
import { TotpCredential } from '../../../src/models/totpCredentials.js';
import { hardRevokeSession } from '../../../src/services/sessionService.js';
import { buildCredential } from '../../factories/credentialFactory.js';
import { buildSession } from '../../factories/sessionFactory.js';

let app: Application;

beforeAll(async () => {
  app = await createApp();
});

beforeEach(() => {
  vi.clearAllMocks();
});

describe('GET /admin/users', () => {
  it('returns users list', async () => {
    (User.findAll as any).mockResolvedValue([buildUser()]);
    (User.count as any).mockResolvedValue(1);

    const res = await request(app).get('/admin/users');

    expect(res.status).toBe(200);
    expect(res.body.users).toHaveLength(1);
    expect(res.body.total).toBe(1);
  });
});

describe('DELETE /admin/users', () => {
  it('deletes user', async () => {
    (User.findOne as any).mockResolvedValue(buildUser());

    const res = await request(app).delete('/admin/users').send({ userId: 'user-1' });

    expect(res.status).toBe(200);
  });

  it('returns 404 if no userId', async () => {
    const res = await request(app).delete('/admin/users').send({});

    expect(res.status).toBe(404);
  });
});

describe('GET /admin/users/:userId', () => {
  it('returns user detail', async () => {
    (User.findByPk as any).mockResolvedValue(buildUser());
    (Session.findAll as any).mockResolvedValue([]);
    (Credential.findAll as any).mockResolvedValue([]);
    (AuthEvent.findAll as any).mockResolvedValue([]);

    const res = await request(app).get(`/admin/users/${testGuid}`);

    expect(res.status).toBe(200);
    expect(res.body.user).toBeDefined();
  });

  it('returns 404 if user missing', async () => {
    (User.findByPk as any).mockResolvedValue(null);

    const res = await request(app).get('/admin/users/user-1');

    expect(res.status).toBe(404);
  });
});

describe('GET /admin/users/:userId/anomalies', () => {
  it('returns anomalies', async () => {
    (AuthEvent.findAll as any).mockResolvedValue([]);

    const res = await request(app).get('/admin/users/user-1/anomalies');

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('suspiciousEvents');
  });
});

describe('GET /admin/sessions', () => {
  it('returns all sessions', async () => {
    (Session.findAll as any).mockResolvedValue([]);
    (Session.count as any).mockResolvedValue(0);

    const res = await request(app).get('/admin/sessions');

    expect(res.status).toBe(200);
    expect(res.body.sessions).toEqual([]);
    expect(Session.findAll).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({
          revokedAt: null,
          replacedBySessionId: null,
        }),
      }),
    );
    expect(Session.count).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({
          revokedAt: null,
          replacedBySessionId: null,
        }),
      }),
    );
  });
});

describe('GET /admin/sessions/:userId', () => {
  it('returns user sessions', async () => {
    (Session.findAll as any).mockResolvedValue([buildSession()]);

    const res = await request(app).get(`/admin/sessions/${testGuid}`);

    expect(res.status).toBe(200);
    expect(res.body.sessions).toHaveLength(1);
    expect(Session.findAll).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({
          userId: testGuid,
          revokedAt: null,
          replacedBySessionId: null,
        }),
      }),
    );
  });
});

describe('DELETE /admin/sessions/by-id/:id', () => {
  it('revokes a single admin-managed session', async () => {
    const session = buildSession({ id: 'session-to-revoke', userId: testGuid });
    (Session.findOne as any).mockResolvedValue(session);

    const res = await request(app).delete('/admin/sessions/by-id/session-to-revoke');

    expect(res.status).toBe(200);
    expect(hardRevokeSession).toHaveBeenCalledWith(session, 'admin_revoke');
  });

  it('returns 404 when a single admin-managed session is missing', async () => {
    (Session.findOne as any).mockResolvedValue(null);

    const res = await request(app).delete('/admin/sessions/by-id/missing-session');

    expect(res.status).toBe(404);
  });
});

describe('DELETE /admin/sessions/:userId/revoke-all', () => {
  it('revokes all sessions', async () => {
    (Session.findAll as any).mockResolvedValue([{ id: 's1' }, { id: 's2' }]);

    const res = await request(app).delete(`/admin/sessions/${testGuid}/revoke-all`);

    expect(res.status).toBe(200);
  });
});

describe('POST /admin/users/:userId/recovery/device-replacement', () => {
  it('revokes sessions, removes passkeys, and disables TOTP for device replacement', async () => {
    const sessions = [buildSession({ id: 's1' }), buildSession({ id: 's2' })];
    const credentials = [buildCredential({ id: 'cred-1' }), buildCredential({ id: 'cred-2' })];

    (Session.findOne as any).mockResolvedValue(
      buildSession({ stepUpVerifiedAt: new Date(), stepUpMethod: 'webauthn' }),
    );
    (User.findByPk as any).mockResolvedValue(buildUser({ id: testGuid }));
    (Session.findAll as any).mockResolvedValue(sessions);
    (Credential.findAll as any).mockResolvedValue(credentials);
    (TotpCredential.update as any).mockResolvedValue([1]);

    const res = await request(app)
      .post(`/admin/users/${testGuid}/recovery/device-replacement`)
      .send({});

    expect(res.status).toBe(200);
    expect(hardRevokeSession).toHaveBeenCalledTimes(2);
    expect(credentials[0].destroy).toHaveBeenCalled();
    expect(credentials[1].destroy).toHaveBeenCalled();
    expect(TotpCredential.update).toHaveBeenCalledWith(
      { enabled: false },
      expect.objectContaining({
        where: expect.objectContaining({ userId: testGuid, enabled: true }),
      }),
    );
    expect(res.body).toEqual({
      userId: testGuid,
      revokedSessions: 2,
      removedCredentials: 2,
      disabledTotpCredentials: 1,
    });
  });

  it('requires a fresh step-up verification', async () => {
    (Session.findOne as any).mockResolvedValue(
      buildSession({ stepUpVerifiedAt: null, stepUpMethod: null }),
    );

    const res = await request(app)
      .post(`/admin/users/${testGuid}/recovery/device-replacement`)
      .send({});

    expect(res.status).toBe(403);
    expect(res.body.error).toBe('step_up_required');
    expect(User.findByPk).not.toHaveBeenCalled();
  });
});

describe('GET /admin/auth-events', () => {
  it('returns events', async () => {
    (AuthEvent.findAll as any).mockResolvedValue([]);
    (AuthEvent.count as any).mockResolvedValue(0);

    const res = await request(app).get('/admin/auth-events');

    expect(res.status).toBe(200);
    expect(res.body.events).toEqual([]);
  });
});

describe('GET /admin/credential-count', () => {
  it('returns count', async () => {
    (Credential.count as any).mockResolvedValue(5);

    const res = await request(app).get('/admin/credential-count');

    expect(res.status).toBe(200);
    expect(res.body.count).toBe(5);
  });
});

describe('POST /admin/users', () => {
  it('creates user successfully', async () => {
    (User.findOne as any).mockResolvedValue(null);

    (User.create as any).mockResolvedValue({
      id: 'user-1',
      email: 'test@example.com',
      phone: '+14155552671',
      roles: ['user'],
    });

    const res = await request(app)
      .post('/admin/users')
      .send({
        email: 'test@example.com',
        phone: '+14155552671',
        roles: ['user'],
      });

    expect(res.status).toBe(201);
    expect(res.body.user).toBeDefined();
  });

  it('creates user with scoped roles', async () => {
    (User.findOne as any).mockResolvedValue(null);

    (User.create as any).mockResolvedValue({
      id: 'user-1',
      email: 'test@example.com',
      phone: '+14155552671',
      roles: ['admin:read'],
    });

    const res = await request(app)
      .post('/admin/users')
      .send({
        email: 'test@example.com',
        phone: '+14155552671',
        roles: ['admin:read'],
      });

    expect(res.status).toBe(201);
    expect(User.create).toHaveBeenCalledWith(
      expect.objectContaining({
        roles: ['admin:read'],
      }),
    );
  });

  it('rejects scoped roles with invalid separators', async () => {
    const res = await request(app)
      .post('/admin/users')
      .send({
        email: 'test@example.com',
        phone: '+14155552671',
        roles: ['admin/read'],
      });

    expect(res.status).toBe(400);
  });

  it('returns 409 if user already exists', async () => {
    (User.findOne as any).mockResolvedValue(buildUser());

    const res = await request(app)
      .post('/admin/users')
      .send({
        email: 'test@example.com',
        phone: '+14155552671',
        roles: ['user'],
      });

    expect(res.status).toBe(409);
  });

  it('returns 400 for invalid payload', async () => {
    const res = await request(app).post('/admin/users').send({});

    expect(res.status).toBe(400);
  });
});

describe('PATCH /admin/users/:userId', () => {
  it('updates user successfully', async () => {
    const user = buildUser();

    (User.findByPk as any).mockResolvedValue(user);

    const res = await request(app)
      .patch('/admin/users/user-1')
      .send({ roles: ['admin'] });

    expect(res.status).toBe(200);
    expect(user.update).toHaveBeenCalled();
  });

  it('updates scoped roles successfully', async () => {
    const user = buildUser();

    (User.findByPk as any).mockResolvedValue(user);

    const res = await request(app)
      .patch('/admin/users/user-1')
      .send({ roles: ['admin:write'] });

    expect(res.status).toBe(200);
    expect(user.update).toHaveBeenCalledWith({ roles: ['admin:write'] });
  });

  it('returns 404 if user not found', async () => {
    (User.findByPk as any).mockResolvedValue(null);

    const res = await request(app)
      .patch('/admin/users/user-1')
      .send({ roles: ['admin'] });

    expect(res.status).toBe(404);
  });

  it('returns 400 for invalid payload', async () => {
    const res = await request(app).patch('/admin/users/user-1').send({}); // empty

    expect(res.status).toBe(400);
  });

  it('returns 400 when missing userId', async () => {
    const res = await request(app)
      .patch('/admin/users/')
      .send({ roles: ['admin'] });

    expect([400, 404]).toContain(res.status);
  });
});
