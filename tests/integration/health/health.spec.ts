import request from 'supertest';
import { createApp } from '../../../src/app';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { Application } from 'express';

import { AuthEventService } from '../../../src/services/authEventService.js';

let app: Application;

beforeAll(async () => {
  app = await createApp();
});

beforeEach(() => {
  vi.clearAllMocks();
});

describe('Health Routes', () => {
  it('returns system status', async () => {
    const res = await request(app).get('/health/status');

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ message: 'System up' });
  });

  it('returns the API version', async () => {
    const res = await request(app).get('/health/version');

    expect(res.status).toBe(200);
    expect(typeof res.body.message).toBe('string');
    expect(res.body.message.length).toBeGreaterThan(0);
  });

  it('returns 404 for unknown health route', async () => {
    const res = await request(app).get('/health/unknown');

    expect(res.status).toBe(404);
    expect(AuthEventService.requestSuspicious).toHaveBeenCalledWith(
      expect.objectContaining({
        originalUrl: '/health/unknown',
      }),
      expect.objectContaining({
        reason: 'Request to an unknown route.',
        path: '/health/unknown',
      }),
    );
  });
});
