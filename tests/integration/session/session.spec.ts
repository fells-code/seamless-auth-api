import request from 'supertest';
import { describe, it, expect, beforeAll, beforeEach, vi } from 'vitest';
import { createApp } from '../../../src/app';
import { Application } from 'express';
import { Op } from 'sequelize';

import { getSystemConfig } from '../../../src/config/getSystemConfig.js';
import { Session } from '../../../src/models/sessions.js';
import { User } from '../../../src/models/users.js';
import { hardRevokeSession } from '../../../src/services/sessionService.js';
import { buildSession } from '../../factories/sessionFactory.js';

let app: Application;

beforeAll(async () => {
  app = await createApp();
});

beforeEach(() => {
  vi.resetModules();
  vi.clearAllMocks();
});

describe('GET /sessions', () => {
  it('returns active sessions', async () => {
    (Session.findAll as any).mockResolvedValue([
      buildSession({ id: 'session-1' }),
      buildSession({ id: 'session-2' }),
    ]);

    const res = await request(app).get('/sessions');

    expect(res.status).toBe(200);
    expect(res.body.sessions).toHaveLength(2);

    const current = res.body.sessions.find((s: any) => s.id === 'session-1');
    expect(current.current).toBe(true);
  });

  it('lists only sessions that are current, not rotated away or expired', async () => {
    (Session.findAll as any).mockResolvedValue([]);

    await request(app).get('/sessions');

    const { where } = (Session.findAll as any).mock.calls[0][0];
    expect(where).toMatchObject({ revokedAt: null, replacedBySessionId: null });
    expect(where.expiresAt[Op.gt]).toBeInstanceOf(Date);
    expect(where.idleExpiresAt[Op.gt]).toBeInstanceOf(Date);
  });

  it('returns empty list', async () => {
    (Session.findAll as any).mockResolvedValue([]);

    const res = await request(app).get('/sessions');

    expect(res.status).toBe(200);
    expect(res.body.sessions).toEqual([]);
  });
});

describe('DELETE /sessions/:id', () => {
  it('revokes a session', async () => {
    const session = buildSession();

    (Session.findOne as any).mockResolvedValue(session);

    const res = await request(app).delete('/sessions/session-1');

    expect(res.status).toBe(200);
    expect(hardRevokeSession).toHaveBeenCalledWith(session, 'user_revoked');
  });

  it('returns 404 if session not found', async () => {
    (Session.findOne as any).mockResolvedValue(null);

    const res = await request(app).delete('/sessions/bad-id');

    expect(res.status).toBe(404);
  });
});

describe('DELETE /sessions', () => {
  it('revokes all sessions in one update and records the cutoff', async () => {
    (Session.update as any).mockResolvedValue([2]);

    const res = await request(app).delete('/sessions');

    expect(res.status).toBe(200);
    expect(Session.update).toHaveBeenCalledWith(
      { revokedAt: expect.any(Date), revokedReason: 'user_logout_all' },
      { where: { userId: expect.any(String), revokedAt: null } },
    );
    expect(User.update).toHaveBeenCalledWith(
      { sessionsRevokedBefore: expect.any(Date) },
      { where: { id: expect.any(String) } },
    );
    expect(Session.findAll).not.toHaveBeenCalled();
  });

  it('handles no sessions gracefully', async () => {
    (Session.findAll as any).mockResolvedValue([]);

    const res = await request(app).delete('/sessions');

    expect(res.status).toBe(200);
    expect(hardRevokeSession).not.toHaveBeenCalled();
  });
});

describe('POST /sessions/exchange', () => {
  const body = {
    grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
    subject_token: 'a.b.c',
    subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
  };

  it('answers invalid_request to a malformed request, with no store', async () => {
    const res = await request(app)
      .post('/sessions/exchange')
      .send({ ...body, grant_type: 'password' });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_request');
  });

  it('answers one body for a token that does not verify', async () => {
    vi.mocked(getSystemConfig).mockResolvedValue({
      oidc_issuer: 'https://login.example.com',
    } as never);

    const res = await request(app).post('/sessions/exchange').send(body);

    expect(res.status).toBe(400);
    expect(res.body).toEqual({ error: 'invalid_request' });
    expect(res.headers['cache-control']).toBe('no-store');
  });
});
