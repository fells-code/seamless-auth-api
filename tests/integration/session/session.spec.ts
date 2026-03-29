import request from 'supertest';
import { describe, it, expect, beforeAll, beforeEach, vi } from 'vitest';
import { createApp } from '../../../src/app';
import { Application } from 'express';

import { Session } from '../../../src/models/sessions.js';
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
  it('revokes all sessions', async () => {
    const sessions = [buildSession({ id: '1' }), buildSession({ id: '2' })];

    (Session.findAll as any).mockResolvedValue(sessions);

    const res = await request(app).delete('/sessions');

    expect(res.status).toBe(200);
    expect(hardRevokeSession).toHaveBeenCalledTimes(2);
  });

  it('handles no sessions gracefully', async () => {
    (Session.findAll as any).mockResolvedValue([]);

    const res = await request(app).delete('/sessions');

    expect(res.status).toBe(200);
    expect(hardRevokeSession).not.toHaveBeenCalled();
  });
});
