import request from 'supertest';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { Application } from 'express';

import { createApp } from '../../../src/app';
import { Credential } from '../../../src/models/credentials.js';
import { User } from '../../../src/models/users.js';
import { buildUser, testGuid } from '../../factories/userFactory';
import { AuthEvent } from '../../../src/models/authEvents.js';
import { Session } from '../../../src/models/sessions.js';
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
  });
});

describe('GET /admin/sessions/:userId', () => {
  it('returns user sessions', async () => {
    (Session.findAll as any).mockResolvedValue([buildSession()]);

    const res = await request(app).get(`/admin/sessions/${testGuid}`);

    expect(res.status).toBe(200);
    expect(res.body.sessions).toHaveLength(1);
  });
});

describe('DELETE /admin/sessions/:userId/revoke-all', () => {
  it('revokes all sessions', async () => {
    (Session.findAll as any).mockResolvedValue([{ id: 's1' }, { id: 's2' }]);

    const res = await request(app).delete(`/admin/sessions/${testGuid}/revoke-all`);

    expect(res.status).toBe(200);
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
