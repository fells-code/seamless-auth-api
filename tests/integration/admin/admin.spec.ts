import request from 'supertest';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { Application } from 'express';
import { Op } from 'sequelize';

import { createApp } from '../../../src/app';
import { Credential } from '../../../src/models/credentials.js';
import { User } from '../../../src/models/users.js';
import { buildUser, testGuid } from '../../factories/userFactory';
import { AuthEvent } from '../../../src/models/authEvents.js';
import { AuthEventService } from '../../../src/services/authEventService.js';
import { Session } from '../../../src/models/sessions.js';
import { TotpCredential } from '../../../src/models/totpCredentials.js';
import { hardRevokeSession } from '../../../src/services/sessionService.js';
import {
  createUser,
  getAuthEvents,
  recoverUserForDeviceReplacement,
  updateUser,
} from '../../../src/controllers/admin.js';
import { buildCredential } from '../../factories/credentialFactory.js';
import { buildSession } from '../../factories/sessionFactory.js';
import { getSystemConfig } from '../../../src/config/getSystemConfig.js';
import { buildSystemConfig } from '../../factories/systemConfigFactory.js';

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
    expect(JSON.stringify(res.body)).not.toContain('challenge');
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
    (User.findByPk as any).mockResolvedValue(
      buildUser({
        emailVerificationToken: 'email-token',
        phoneVerificationToken: 'phone-token',
        challengeContext: { prfSalt: 'salt' },
      }),
    );
    (Session.findAll as any).mockResolvedValue([
      buildSession({
        refreshTokenHash: 'refresh-hash',
        refreshTokenLookup: 'refresh-lookup',
        idleExpiresAt: new Date(),
      }),
    ]);
    (Credential.findAll as any).mockResolvedValue([
      buildCredential({
        publicKey: 'public-key',
      }),
    ]);
    (AuthEvent.findAll as any).mockResolvedValue([]);

    const res = await request(app).get(`/admin/users/${testGuid}`);

    expect(res.status).toBe(200);
    expect(res.body.user).toBeDefined();
    expect(res.body.sessions).toHaveLength(1);
    expect(res.body.credentials).toHaveLength(1);
    expect(JSON.stringify(res.body)).not.toContain('emailVerificationToken');
    expect(JSON.stringify(res.body)).not.toContain('phoneVerificationToken');
    expect(JSON.stringify(res.body)).not.toContain('challengeContext');
    expect(JSON.stringify(res.body)).not.toContain('refreshTokenHash');
    expect(JSON.stringify(res.body)).not.toContain('refreshTokenLookup');
    expect(JSON.stringify(res.body)).not.toContain('publicKey');
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

const validProofing = { method: 'in_person', evidenceRef: 'TICKET-1042' };

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
      .send({ proofing: validProofing });

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
      .send({ proofing: validProofing });

    expect(res.status).toBe(403);
    expect(res.body.error).toBe('step_up_required');
    expect(User.findByPk).not.toHaveBeenCalled();
  });
});

describe('device replacement identity proofing', () => {
  beforeEach(() => {
    (Session.findOne as any).mockResolvedValue(
      buildSession({ stepUpVerifiedAt: new Date(), stepUpMethod: 'webauthn' }),
    );
    (User.findByPk as any).mockResolvedValue(buildUser({ id: testGuid }));
    (Session.findAll as any).mockResolvedValue([]);
    (Credential.findAll as any).mockResolvedValue([]);
    (TotpCredential.update as any).mockResolvedValue([0]);
  });

  it('refuses a recovery that records no proofing', async () => {
    const res = await request(app)
      .post(`/admin/users/${testGuid}/recovery/device-replacement`)
      .send({});

    expect(res.status).toBe(400);
    expect(hardRevokeSession).not.toHaveBeenCalled();
  });

  it('refuses a remote exception with no named approver', async () => {
    const res = await request(app)
      .post(`/admin/users/${testGuid}/recovery/device-replacement`)
      .send({ proofing: { method: 'remote_exception', evidenceRef: 'TICKET-7' } });

    expect(res.status).toBe(400);
    expect(hardRevokeSession).not.toHaveBeenCalled();
  });

  it('accepts a remote exception once an approver is named', async () => {
    const res = await request(app)
      .post(`/admin/users/${testGuid}/recovery/device-replacement`)
      .send({
        proofing: { method: 'remote_exception', evidenceRef: 'TICKET-7', approver: 'j.reyes' },
      });

    expect(res.status).toBe(200);
  });

  it('records the proofing and names the actor separately from the target', async () => {
    await request(app)
      .post(`/admin/users/${testGuid}/recovery/device-replacement`)
      .send({ proofing: validProofing });

    const call = (AuthEventService.log as any).mock.calls
      .map(([arg]: [any]) => arg)
      .find((arg: any) => arg.type === 'admin_device_replacement_recovery');

    expect(call).toBeDefined();
    expect(call.metadata.proofing).toEqual({
      method: 'in_person',
      evidenceRef: 'TICKET-1042',
    });
    expect(call.actorUserId).toBeTruthy();
    expect(call.actorUserId).not.toBe(testGuid);
    expect(call.userId).toBe(testGuid);
  });

  it('distinguishes a remote exception in the audit trail', async () => {
    await request(app)
      .post(`/admin/users/${testGuid}/recovery/device-replacement`)
      .send({
        proofing: { method: 'remote_exception', evidenceRef: 'TICKET-7', approver: 'j.reyes' },
      });

    const call = (AuthEventService.log as any).mock.calls
      .map(([arg]: [any]) => arg)
      .find((arg: any) => arg.type === 'admin_device_replacement_recovery');

    expect(call.metadata.proofing).toEqual({
      method: 'remote_exception',
      evidenceRef: 'TICKET-7',
      approver: 'j.reyes',
    });
  });
});

describe('admin actions are attributed', () => {
  function adminEventsOfType(type: string) {
    return (AuthEventService.log as any).mock.calls
      .map(([arg]: [any]) => arg)
      .filter((arg: any) => arg.type === type);
  }

  it('records a user deletion, naming the actor and the target', async () => {
    const user = buildUser({ id: testGuid });
    (User.findOne as any).mockResolvedValue(user);

    const res = await request(app).delete('/admin/users').send({ userId: testGuid });

    expect(res.status).toBe(200);
    expect(user.destroy).toHaveBeenCalled();

    const [event] = adminEventsOfType('user_deleted');
    expect(event).toBeDefined();
    expect(event.userId).toBe(testGuid);
    expect(event.actorUserId).toBeTruthy();
    expect(event.actorUserId).not.toBe(testGuid);
  });

  it('records a bulk session revoke', async () => {
    (Session.findAll as any).mockResolvedValue([
      buildSession({ id: 's1' }),
      buildSession({ id: 's2' }),
    ]);

    const res = await request(app).delete(`/admin/sessions/${testGuid}/revoke-all`);

    expect(res.status).toBe(200);

    const [event] = adminEventsOfType('admin_session_revoked');
    expect(event).toBeDefined();
    expect(event.userId).toBe(testGuid);
    expect(event.actorUserId).toBeTruthy();
    expect(event.metadata).toMatchObject({ revokedSessions: 2, scope: 'all' });
  });
});

describe('GET /admin/auth-events', () => {
  it('filters by acting administrator', async () => {
    (AuthEvent.findAll as any).mockResolvedValue([]);
    (AuthEvent.count as any).mockResolvedValue(0);

    const res = await request(app).get('/admin/auth-events').query({ actorUserId: 'admin-9' });

    expect(res.status).toBe(200);
    expect(AuthEvent.findAll).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({ actor_user_id: 'admin-9' }),
      }),
    );
  });

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
      challenge: 'challenge',
      emailVerificationToken: 'email-token',
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
    expect(res.body.user).not.toHaveProperty('challenge');
    expect(res.body.user).not.toHaveProperty('emailVerificationToken');
  });

  it('creates user without a phone number', async () => {
    (User.findOne as any).mockResolvedValue(null);

    (User.create as any).mockResolvedValue({
      id: 'user-1',
      email: 'test@example.com',
      phone: null,
      roles: ['user'],
    });

    const res = await request(app)
      .post('/admin/users')
      .send({
        email: 'test@example.com',
        roles: ['user'],
      });

    expect(res.status).toBe(201);
    expect(User.create).toHaveBeenCalledWith(
      expect.objectContaining({
        email: 'test@example.com',
        phone: null,
        roles: ['user'],
      }),
    );
  });

  it('normalizes optional phone numbers on create', async () => {
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
        phone: '+1 (415) 555-2671',
        roles: ['user'],
      });

    expect(res.status).toBe(201);
    expect(User.create).toHaveBeenCalledWith(
      expect.objectContaining({
        phone: '+14155552671',
      }),
    );
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

  it('rejects a role that is not in available_roles', async () => {
    (getSystemConfig as any).mockResolvedValue(
      buildSystemConfig({ available_roles: ['user', 'admin', 'admin:read', 'admin:write'] }),
    );

    const res = await request(app)
      .post('/admin/users')
      .send({ email: 'test@example.com', roles: ['admin:reed'] });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('Invalid roles');
    expect(res.body.details.roles).toEqual(['admin:reed']);
    expect(User.create).not.toHaveBeenCalled();
  });

  it('accepts a scoped role that is in available_roles', async () => {
    (getSystemConfig as any).mockResolvedValue(
      buildSystemConfig({ available_roles: ['user', 'admin', 'admin:read', 'admin:write'] }),
    );
    (User.findOne as any).mockResolvedValue(null);
    (User.create as any).mockResolvedValue(buildUser({ roles: ['admin:read'] }));

    const res = await request(app)
      .post('/admin/users')
      .send({ email: 'test@example.com', roles: ['admin:read'] });

    expect(res.status).toBe(201);
  });

  it('skips validation when the role catalog is empty', async () => {
    (getSystemConfig as any).mockResolvedValue(buildSystemConfig({ available_roles: [] }));
    (User.findOne as any).mockResolvedValue(null);
    (User.create as any).mockResolvedValue(buildUser({ roles: ['anything'] }));

    const res = await request(app)
      .post('/admin/users')
      .send({ email: 'test@example.com', roles: ['anything'] });

    expect(res.status).toBe(201);
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
    expect(res.body.user).not.toHaveProperty('challenge');
    expect(res.body.user).not.toHaveProperty('challengeContext');
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

  it('rejects an update to a role that is not in available_roles', async () => {
    (getSystemConfig as any).mockResolvedValue(
      buildSystemConfig({ available_roles: ['user', 'admin', 'admin:read', 'admin:write'] }),
    );

    const res = await request(app)
      .patch('/admin/users/user-1')
      .send({ roles: ['admin:readonly'] });

    expect(res.status).toBe(400);
    expect(res.body.details.roles).toEqual(['admin:readonly']);
    expect(User.findByPk).not.toHaveBeenCalled();
  });

  it('clears phone state when phone is removed', async () => {
    const user = buildUser({ phone: '+14155552671', phoneVerified: true });

    (User.findByPk as any).mockResolvedValue(user);

    const res = await request(app).patch('/admin/users/user-1').send({ phone: null });

    expect(res.status).toBe(200);
    expect(user.update).toHaveBeenCalledWith({
      phone: null,
      phoneVerified: false,
      phoneVerificationToken: null,
      phoneVerificationTokenExpiry: null,
    });
  });

  it('rejects phoneVerified true without a phone number', async () => {
    const user = buildUser({ phone: null, phoneVerified: false });

    (User.findByPk as any).mockResolvedValue(user);

    const res = await request(app).patch('/admin/users/user-1').send({ phoneVerified: true });

    expect(res.status).toBe(400);
    expect(user.update).not.toHaveBeenCalled();
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

  it('rejects an invalid phone number on update', async () => {
    (User.findByPk as any).mockResolvedValue(buildUser());

    const res = await request(app).patch('/admin/users/user-1').send({ phone: '11111' });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('Invalid update payload');
    expect(User.findByPk).toHaveBeenCalled();
  });

  it('resets phoneVerified when the phone number changes', async () => {
    const user = buildUser({ phone: '+14155552671', phoneVerified: true });

    (User.findByPk as any).mockResolvedValue(user);

    const res = await request(app).patch('/admin/users/user-1').send({ phone: '+14155552672' });

    expect(res.status).toBe(200);
    expect(user.update).toHaveBeenCalledWith(
      expect.objectContaining({ phone: '+14155552672', phoneVerified: false }),
    );
  });

  it('keeps phoneVerified when explicitly supplied alongside a new phone', async () => {
    const user = buildUser({ phone: '+14155552671', phoneVerified: false });

    (User.findByPk as any).mockResolvedValue(user);

    const res = await request(app)
      .patch('/admin/users/user-1')
      .send({ phone: '+14155552672', phoneVerified: true });

    expect(res.status).toBe(200);
    expect(user.update).toHaveBeenCalledWith(
      expect.objectContaining({ phone: '+14155552672', phoneVerified: true }),
    );
  });

  it('returns 500 when the user update fails', async () => {
    const user = buildUser();
    (user.update as any).mockRejectedValue(new Error('boom'));
    (User.findByPk as any).mockResolvedValue(user);

    const res = await request(app)
      .patch('/admin/users/user-1')
      .send({ roles: ['admin'] });

    expect(res.status).toBe(500);
    expect(res.body.error).toBe('Failed to update user');
  });

  it('returns 400 when the user lookup throws', async () => {
    (User.findByPk as any).mockRejectedValue(new Error('boom'));

    const res = await request(app)
      .patch('/admin/users/user-1')
      .send({ roles: ['admin'] });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('Could not update users');
  });
});

describe('GET /admin/users (additional branches)', () => {
  it('filters users by a search term', async () => {
    (User.findAll as any).mockResolvedValue([buildUser()]);
    (User.count as any).mockResolvedValue(1);

    const res = await request(app).get('/admin/users').query({ search: 'example' });

    expect(res.status).toBe(200);
    const where = (User.findAll as any).mock.calls[0][0].where;
    expect(where[Op.or]).toBeDefined();
  });

  it('returns an empty list when findAll resolves null', async () => {
    (User.findAll as any).mockResolvedValue(null);
    (User.count as any).mockResolvedValue(0);

    const res = await request(app).get('/admin/users');

    expect(res.status).toBe(200);
    expect(res.body.users).toEqual([]);
  });
});

describe('POST /admin/users (additional branches)', () => {
  it('rejects an invalid phone number', async () => {
    const res = await request(app)
      .post('/admin/users')
      .send({ email: 'test@example.com', phone: '11111', roles: ['user'] });

    expect(res.status).toBe(400);
    expect(res.body.details.phone).toBe('Invalid phone number');
    expect(User.findOne).not.toHaveBeenCalled();
  });

  it('returns 500 when creation fails', async () => {
    (User.findOne as any).mockRejectedValue(new Error('boom'));

    const res = await request(app)
      .post('/admin/users')
      .send({ email: 'test@example.com', phone: '+14155552671', roles: ['user'] });

    expect(res.status).toBe(500);
    expect(res.body.error).toBe('Failed to create user');
  });
});

describe('DELETE /admin/users (additional branches)', () => {
  it('returns 200 when the user cannot be found for deletion', async () => {
    (User.findOne as any).mockResolvedValue(null);

    const res = await request(app).delete('/admin/users').send({ userId: 'missing' });

    expect(res.status).toBe(200);
  });

  it('returns 500 when the deletion lookup throws', async () => {
    (User.findOne as any).mockRejectedValue(new Error('boom'));

    const res = await request(app).delete('/admin/users').send({ userId: 'user-1' });

    expect(res.status).toBe(500);
    expect(res.body.error).toBe('Failed');
  });
});

describe('GET /admin/users/:userId/anomalies (additional branches)', () => {
  it('aggregates related ips and agents', async () => {
    (AuthEvent.findAll as any)
      .mockResolvedValueOnce([
        { ip_address: '1.1.1.1', user_agent: 'UA' },
        { ip_address: null, user_agent: null },
      ])
      .mockResolvedValueOnce([]);

    const res = await request(app).get('/admin/users/user-1/anomalies');

    expect(res.status).toBe(200);
    expect(res.body.relatedIps).toEqual(['1.1.1.1']);
    expect(res.body.relatedAgents).toEqual(['UA']);
  });

  it('returns 500 when the anomaly lookup fails', async () => {
    (AuthEvent.findAll as any).mockRejectedValue(new Error('boom'));

    const res = await request(app).get('/admin/users/user-1/anomalies');

    expect(res.status).toBe(500);
    expect(res.body.error).toBe('Failed to fetch anomalies');
  });
});

describe('admin session failure paths', () => {
  it('returns 500 when fetching user sessions fails', async () => {
    (Session.findAll as any).mockRejectedValue(new Error('boom'));

    const res = await request(app).get(`/admin/sessions/${testGuid}`);

    expect(res.status).toBe(500);
    expect(res.body.error).toBe('Failed to fetch sessions');
  });

  it('returns 500 when revoking all sessions fails', async () => {
    (Session.findAll as any).mockRejectedValue(new Error('boom'));

    const res = await request(app).delete(`/admin/sessions/${testGuid}/revoke-all`);

    expect(res.status).toBe(500);
    expect(res.body.error).toBe('Failed to revoke sessions');
  });

  it('returns 500 when a single session revoke fails', async () => {
    (Session.findOne as any).mockRejectedValue(new Error('boom'));

    const res = await request(app).delete('/admin/sessions/by-id/session-x');

    expect(res.status).toBe(500);
    expect(res.body.error).toBe('Failed to revoke session');
  });
});

describe('POST /admin/users/:userId/recovery/device-replacement (additional branches)', () => {
  it('returns 404 when the recovery target is missing', async () => {
    (Session.findOne as any).mockResolvedValue(
      buildSession({ stepUpVerifiedAt: new Date(), stepUpMethod: 'webauthn' }),
    );
    (User.findByPk as any).mockResolvedValue(null);

    const res = await request(app)
      .post(`/admin/users/${testGuid}/recovery/device-replacement`)
      .send({ proofing: validProofing });

    expect(res.status).toBe(404);
    expect(res.body.error).toBe('User not found');
  });

  it('skips every action when all recovery flags are false', async () => {
    (Session.findOne as any).mockResolvedValue(
      buildSession({ stepUpVerifiedAt: new Date(), stepUpMethod: 'webauthn' }),
    );
    (User.findByPk as any).mockResolvedValue(buildUser({ id: testGuid }));

    const res = await request(app)
      .post(`/admin/users/${testGuid}/recovery/device-replacement`)
      .send({
        proofing: validProofing,
        revokeSessions: false,
        removePasskeys: false,
        disableTotp: false,
      });

    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      userId: testGuid,
      revokedSessions: 0,
      removedCredentials: 0,
      disabledTotpCredentials: 0,
    });
    expect(hardRevokeSession).not.toHaveBeenCalled();
    expect(TotpCredential.update).not.toHaveBeenCalled();
  });
});

describe('GET /admin/auth-events (additional branches)', () => {
  it('expands type filters and applies date and user filters', async () => {
    (AuthEvent.findAll as any).mockResolvedValue([]);
    (AuthEvent.count as any).mockResolvedValue(0);

    const res = await request(app)
      .get('/admin/auth-events')
      .query({
        type: ['login', 'otp', 'webauthn', 'magicLink', 'suspicious', 'custom'],
        from: '2026-01-01',
        to: '2026-02-01',
        userId: 'user-1',
      });

    expect(res.status).toBe(200);
    const where = (AuthEvent.findAll as any).mock.calls[0][0].where;
    expect(where.user_id).toBe('user-1');
    expect(where.created_at).toBeDefined();
    expect(where.type[Op.in]).toEqual(
      expect.arrayContaining([
        'login_success',
        'otp_success',
        'webauthn_login_success',
        'magic_link_success',
        'login_suspicious',
        'custom',
      ]),
    );
  });

  it('returns 500 when the auth events lookup fails', async () => {
    (AuthEvent.findAll as any).mockRejectedValue(new Error('boom'));
    (AuthEvent.count as any).mockResolvedValue(0);

    const res = await request(app).get('/admin/auth-events');

    expect(res.status).toBe(500);
    expect(res.body.error).toBe('Failed to fetch events');
  });
});

describe('GET /admin/credential-count (additional branches)', () => {
  it('returns 500 when the credential count fails', async () => {
    (Credential.count as any).mockRejectedValue(new Error('boom'));

    const res = await request(app).get('/admin/credential-count');

    expect(res.status).toBe(500);
    expect(res.body.error).toBe('Failed to fetch credential count');
  });
});

describe('admin controller guards (direct invocation)', () => {
  function mockRes() {
    const res: any = {};
    res.status = vi.fn().mockReturnValue(res);
    res.json = vi.fn().mockReturnValue(res);
    return res;
  }

  it('rejects createUser with an invalid body', async () => {
    const res = mockRes();

    await createUser({ body: {} } as any, res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ error: 'Invalid payload' }));
  });

  it('rejects updateUser when the user id is missing', async () => {
    const res = mockRes();

    await updateUser({ params: {}, body: { roles: ['admin'] } } as any, res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ error: 'Bad request' });
  });

  it('rejects device-replacement recovery with an invalid body', async () => {
    const res = mockRes();

    await recoverUserForDeviceReplacement(
      { params: { userId: testGuid }, body: { revokeSessions: 'nope' } } as any,
      res,
    );

    expect(res.status).toHaveBeenCalledWith(400);
    expect(User.findByPk).not.toHaveBeenCalled();
  });

  it('rejects getAuthEvents with an invalid query', async () => {
    const res = mockRes();

    await getAuthEvents({ query: { limit: '5000' } } as any, res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ error: 'Invalid query params' });
  });
});

describe('getDatabaseSize', () => {
  it('returns the numeric database size', async () => {
    const index = await import('../../../src/models/index.js');
    const spy = vi.spyOn(index, 'getSequelize').mockReturnValue({
      query: vi.fn().mockResolvedValue([[{ size: '4096' }]]),
    } as any);

    const { getDatabaseSize } = await import('../../../src/controllers/admin.js');

    await expect(getDatabaseSize()).resolves.toBe(4096);
    spy.mockRestore();
  });
});
