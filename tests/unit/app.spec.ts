import request from 'supertest';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';

import app, { createApp } from '../../src/app.js';
import { AuthEventService } from '../../src/services/authEventService.js';

let built: Awaited<ReturnType<typeof createApp>>;

beforeAll(async () => {
  app.get('/__test_cors_error', (_req, _res, next) => next(new Error('Not allowed by CORS')));
  app.get('/__test_boom', (_req, _res, next) => {
    // A non-standard error whose `message` access throws forces the first
    // error handler to fail, exercising the fallback 500 handler.
    const malformed = {};
    Object.defineProperty(malformed, 'message', {
      get() {
        throw new Error('boom');
      },
    });
    next(malformed);
  });
  app.get('/__test_plain_error', (_req, _res, next) => next(new Error('plain failure')));
  built = await createApp();
});

describe('CORS origin handling', () => {
  it('reflects an allowlisted origin', async () => {
    const res = await request(built)
      .get('/__definitely_not_a_route')
      .set('Origin', 'http://localhost:5137');

    expect(res.headers['access-control-allow-origin']).toBe('http://localhost:5137');
  });

  it('flags and does not reflect an unknown origin', async () => {
    const res = await request(built)
      .get('/__definitely_not_a_route')
      .set('Origin', 'http://evil.example');

    expect(res.headers['access-control-allow-origin']).toBeUndefined();
    expect(AuthEventService.requestSuspiciousContext).toHaveBeenCalled();
  });
});

describe('developer endpoints', () => {
  it('serves the generated OpenAPI document in dev', async () => {
    const res = await request(built).get('/openapi.json');

    expect(res.status).toBe(200);
    expect(res.body.openapi).toBe('3.0.3');
    expect(res.body.components.securitySchemes.bearerAuth).toBeDefined();
  });
});

describe('createApp error handling', () => {
  it('passes non-CORS errors through to the not-found handler', async () => {
    const res = await request(built).get('/__test_plain_error');

    expect(res.status).toBe(404);
    expect(res.body).toEqual({ error: 'Not Found' });
  });

  it('returns 403 with a CORS message when a request is rejected by CORS', async () => {
    const res = await request(built).get('/__test_cors_error');

    expect(res.status).toBe(403);
    expect(res.body).toEqual({ message: 'CORS policy does not allow this origin.' });
    expect(res.headers['access-control-allow-origin']).toBe('http://localhost:5137');
    expect(AuthEventService.requestSuspicious).toHaveBeenCalled();
  });

  it('falls back to a 500 when the error pipeline itself throws', async () => {
    const res = await request(built).get('/__test_boom');

    expect(res.status).toBe(500);
    expect(res.body).toEqual({ error: 'Internal server error' });
  });

  it('returns 404 and records suspicious activity for an unknown route', async () => {
    const res = await request(built).get('/__definitely_not_a_route');

    expect(res.status).toBe(404);
    expect(res.body).toEqual({ error: 'Not Found' });
    expect(AuthEventService.requestSuspicious).toHaveBeenCalled();
  });
});

describe('TRUST_PROXY', () => {
  // The setting is applied while the module body runs, so each case needs a fresh import.
  async function loadApp(trustProxy: string) {
    vi.resetModules();
    vi.stubEnv('TRUST_PROXY', trustProxy);

    const { default: freshApp } = await import('../../src/app.js');
    return freshApp;
  }

  afterEach(() => {
    vi.unstubAllEnvs();
    vi.resetModules();
  });

  it('leaves X-Forwarded-For untrusted when unset', async () => {
    const freshApp = await loadApp('');

    expect(freshApp.get('trust proxy')).toBe(false);
  });

  it('resolves the client address through the given number of hops', async () => {
    const freshApp = await loadApp('1');
    freshApp.get('/__test_client_ip', (req, res) => {
      res.json({ ip: req.ip });
    });

    expect(freshApp.get('trust proxy')).toBe(1);

    const res = await request(freshApp)
      .get('/__test_client_ip')
      .set('X-Forwarded-For', '203.0.113.7');

    expect(res.body.ip).toBe('203.0.113.7');
  });

  it('passes a non-numeric setting through to Express', async () => {
    const freshApp = await loadApp('loopback');

    expect(freshApp.get('trust proxy')).toBe('loopback');
  });
});
