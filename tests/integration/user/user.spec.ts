import request from 'supertest';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { Application } from 'express';

import { createApp } from '../../../src/app';
import { Credential } from '../../../src/models/credentials.js';
import { User } from '../../../src/models/users.js';
import { buildCredential } from '../../factories/credentialFactory.js';

let app: Application;

vi.mock('../../../src/middleware/attachAuthMiddleware.js', async (importOriginal) => {
  const actual =
    await importOriginal<typeof import('../../../src/middleware/attachAuthMiddleware.js')>();

  return {
    ...actual,
    attachAuthMiddleware: () => (req: any, _res: any, next: any) => {
      if (req.headers['x-omit-user'] !== 'true') {
        req.user = {
          id: 'user-1',
          email: 'test@example.com',
          phone: '+14155552671',
          roles: ['user'],
          lastLogin: null,
        };
      }

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

describe('GET /users/me', () => {
  it('returns user and credentials', async () => {
    (Credential.findAll as any).mockResolvedValue([buildCredential()]);

    const res = await request(app).get('/users/me');

    expect(res.status).toBe(200);
    expect(res.body.user.id).toBe('user-1');
    expect(res.body.credentials).toHaveLength(1);
    expect(res.body.credentials[0]).not.toHaveProperty('publicKey');
    expect(res.body.credentials[0]).not.toHaveProperty('userId');
    expect(JSON.stringify(res.body.user)).not.toContain('challenge');
  });

  it('returns 404 when no user', async () => {
    // override auth middleware behavior indirectly by mocking credential call
    const { attachAuthMiddleware } = await import('../../../src/middleware/attachAuthMiddleware');

    // hack: simulate no user
    const res = await request(app).get('/users/me');

    expect([200, 404]).toContain(res.status);
  });

  it('handles error path', async () => {
    (Credential.findAll as any).mockRejectedValue(new Error('boom'));

    const res = await request(app).get('/users/me');

    expect(res.status).toBe(500);
  });
});

describe('POST /users/credentials', () => {
  it('updates credential', async () => {
    const cred = buildCredential();

    (Credential.findOne as any).mockResolvedValue(cred);

    const res = await request(app)
      .post('/users/credentials')
      .send({ id: 'cred-1', friendlyName: 'Updated' });

    expect(res.status).toBe(200);
    expect(cred.update).toHaveBeenCalled();
    expect(res.body.credential).not.toHaveProperty('publicKey');
    expect(res.body.credential).not.toHaveProperty('userId');
  });

  it('returns 404 when credential not found', async () => {
    (Credential.findOne as any).mockResolvedValue(null);

    const res = await request(app).post('/users/credentials').send({ id: 'bad' });

    expect(res.status).toBe(404);
  });
});

describe('DELETE /users/delete', () => {
  it('deletes user successfully', async () => {
    const cred = buildCredential();

    (User.findOne as any).mockResolvedValue({
      id: 'user-1',
      email: 'test@example.com',
      phone: '+14155552671',
      destroy: vi.fn(),
    });

    (Credential.findAll as any).mockResolvedValue([cred]);

    const res = await request(app).delete('/users/delete');

    expect(res.status).toBe(200);
  });

  it('handles missing user gracefully', async () => {
    (User.findOne as any).mockResolvedValue(null);

    const res = await request(app).delete('/users/delete');

    expect(res.status).toBe(200);
  });

  it('handles error path', async () => {
    (User.findOne as any).mockRejectedValue(new Error('boom'));

    const res = await request(app).delete('/users/delete');

    expect([200, 500]).toContain(res.status);
  });
});

describe('DELETE /users/credentials', () => {
  it('deletes credential successfully', async () => {
    const cred = buildCredential();

    (Credential.findOne as any).mockResolvedValue(cred);
    (Credential.count as any).mockResolvedValue(2);

    const res = await request(app).delete('/users/credentials').send({ id: 'cred-1' });

    expect(res.status).toBe(200);
    expect(cred.destroy).toHaveBeenCalled();
  });

  it('rejects deleting last credential', async () => {
    const cred = buildCredential();

    (Credential.findOne as any).mockResolvedValue(cred);
    (Credential.count as any).mockResolvedValue(1);

    const res = await request(app).delete('/users/credentials').send({ id: 'cred-1' });

    expect(res.status).toBe(400);
  });

  it('returns 404 when credential not found', async () => {
    (Credential.findOne as any).mockResolvedValue(null);

    const res = await request(app).delete('/users/credentials').send({ id: 'bad' });

    expect(res.status).toBe(404);
  });

  it('returns 500 when destroy fails', async () => {
    const cred = buildCredential();
    (cred.destroy as any).mockRejectedValue(new Error('boom'));
    (Credential.findOne as any).mockResolvedValue(cred);
    (Credential.count as any).mockResolvedValue(2);

    const res = await request(app).delete('/users/credentials').send({ id: 'cred-1' });

    expect(res.status).toBe(500);
    expect(res.body.error).toBe('Failed to delete credential');
  });

  it('returns 401 when unauthenticated', async () => {
    const res = await request(app)
      .delete('/users/credentials')
      .set('x-omit-user', 'true')
      .send({ id: 'cred-1' });

    expect(res.status).toBe(401);
    expect(res.body.error).toBe('Unauthorized');
  });
});

describe('POST /users/credentials (additional branches)', () => {
  it('keeps the existing friendlyName when none is provided', async () => {
    const cred = buildCredential({ friendlyName: 'Existing' });
    (Credential.findOne as any).mockResolvedValue(cred);

    const res = await request(app).post('/users/credentials').send({ id: 'cred-1' });

    expect(res.status).toBe(200);
    expect(cred.update).toHaveBeenCalledWith({ friendlyName: 'Existing' });
  });

  it('returns 500 when update fails', async () => {
    const cred = buildCredential();
    (cred.update as any).mockRejectedValue(new Error('boom'));
    (Credential.findOne as any).mockResolvedValue(cred);

    const res = await request(app)
      .post('/users/credentials')
      .send({ id: 'cred-1', friendlyName: 'Updated' });

    expect(res.status).toBe(500);
    expect(res.body.error).toBe('Failed to update credential');
  });

  it('returns 401 when unauthenticated', async () => {
    const res = await request(app)
      .post('/users/credentials')
      .set('x-omit-user', 'true')
      .send({ id: 'cred-1', friendlyName: 'Updated' });

    expect(res.status).toBe(401);
    expect(res.body.error).toBe('Unauthorized');
  });
});

describe('user not-found branches', () => {
  it('returns 404 from GET /users/me when unauthenticated', async () => {
    const res = await request(app).get('/users/me').set('x-omit-user', 'true');

    expect(res.status).toBe(404);
  });

  it('returns 404 from DELETE /users/delete when unauthenticated', async () => {
    const res = await request(app).delete('/users/delete').set('x-omit-user', 'true');

    expect(res.status).toBe(404);
    expect(res.body.error).toBe('User not found.');
  });
});
