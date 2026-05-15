import { Application } from 'express';
import request from 'supertest';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import { createApp } from '../../../src/app.js';
import { Session } from '../../../src/models/sessions.js';
import { buildSession } from '../../factories/sessionFactory.js';

let app: Application;

beforeAll(async () => {
  app = await createApp();
});

beforeEach(() => {
  vi.clearAllMocks();
});

describe('GET /step-up/status', () => {
  it('returns freshness for the current session', async () => {
    (Session.findOne as any).mockResolvedValue(
      buildSession({
        stepUpVerifiedAt: new Date(),
        stepUpMethod: 'webauthn',
      }),
    );

    const res = await request(app).get('/step-up/status');

    expect(res.status).toBe(200);
    expect(res.body).toEqual(
      expect.objectContaining({
        fresh: true,
        method: 'webauthn',
        maxAgeSeconds: 300,
      }),
    );
  });
});
