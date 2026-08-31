import type { AddressInfo } from 'net';
import request from 'supertest';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';

import app, { createApp } from '../../src/app.js';
import { AuthEventService } from '../../src/services/authEventService.js';

let built: Awaited<ReturnType<typeof createApp>>;

const routeRan = vi.fn();

beforeAll(async () => {
  app.get('/__test_route_ran', (_req, res) => {
    routeRan();
    res.status(200).json({ ok: true });
  });
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
  app.get('/__test_query', (req, res) => {
    res.status(200).json({ query: req.query });
  });
  built = await createApp();
});

describe('CORS origin handling', () => {
  it('reflects an allowlisted origin', async () => {
    const res = await request(built)
      .get('/__definitely_not_a_route')
      .set('Origin', 'http://localhost:5137');

    expect(res.headers['access-control-allow-origin']).toBe('http://localhost:5137');
  });

  it('allows a request that carries no origin at all', async () => {
    const res = await request(built).get('/__test_route_ran');

    expect(res.status).toBe(200);
    expect(routeRan).toHaveBeenCalled();
  });

  it("allows a request from this server's own origin, which the console relies on", async () => {
    const server = built.listen(0);
    const { port } = server.address() as AddressInfo;

    try {
      const res = await request(server)
        .get('/__test_route_ran')
        .set('Origin', `http://127.0.0.1:${port}`);

      expect(res.status).toBe(200);
      expect(res.headers['access-control-allow-origin']).toBe(`http://127.0.0.1:${port}`);
    } finally {
      server.close();
    }
  });

  it('refuses an unknown origin with a 403, and does not run the route', async () => {
    const res = await request(built).get('/__test_route_ran').set('Origin', 'http://evil.example');

    expect(res.status).toBe(403);
    expect(res.body).toEqual({ message: 'CORS policy does not allow this origin.' });
    expect(routeRan).not.toHaveBeenCalled();
    expect(res.headers['access-control-allow-origin']).toBeUndefined();
    expect(AuthEventService.requestSuspicious).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({
        reason: 'Request from an unexpected origin',
        origin: 'http://evil.example',
      }),
    );
  });

  it('refuses a preflight from an unknown origin rather than answering it', async () => {
    const res = await request(built)
      .options('/__test_route_ran')
      .set('Origin', 'http://evil.example')
      .set('Access-Control-Request-Method', 'GET');

    expect(res.status).toBe(403);
  });

  it('refuses an origin when the request carries no host to compare it against', async () => {
    const res = await request(built)
      .get('/__test_route_ran')
      .set('Host', '')
      .set('Origin', 'http://evil.example');

    expect(res.status).toBe(403);
    expect(routeRan).not.toHaveBeenCalled();
  });

  it('refuses an unparseable origin', async () => {
    const res = await request(built).get('/__test_route_ran').set('Origin', 'not-a-url');

    expect(res.status).toBe(403);
    expect(routeRan).not.toHaveBeenCalled();
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

describe('query parsing', () => {
  // Express 5 defaults to the "simple" parser, which would read a[b] as the literal key
  // "a[b]" and drop repeated keys into a different shape than callers were built against.
  it('parses nested and repeated keys the extended way', async () => {
    const res = await request(built).get('/__test_query?a[b]=1&type=x&type=y');

    expect(res.status).toBe(200);
    expect(res.body.query).toEqual({ a: { b: '1' }, type: ['x', 'y'] });
  });
});

describe('createApp error handling', () => {
  it('passes non-CORS errors through to the not-found handler', async () => {
    const res = await request(built).get('/__test_plain_error');

    expect(res.status).toBe(404);
    expect(res.body).toEqual({ error: 'Not Found' });
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
