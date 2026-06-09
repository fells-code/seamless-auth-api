import express, { Router } from 'express';
import request from 'supertest';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { z } from 'zod';

vi.unmock('../../../src/middleware/attachAuthMiddleware.js');

vi.mock('../../../src/openapi/registry.js', () => ({
  registry: {
    registerPath: vi.fn(),
  },
}));

describe('defineRoute auth integration', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('rejects a protected route before handler execution when bearer auth is missing', async () => {
    const { defineRoute } = await import('../../../src/lib/defineRoute.js');
    const { validateBearerToken } = await import('../../../src/services/sessionService.js');
    const handler = vi.fn((_req, res) => res.status(200).json({ message: 'ok' }));
    const app = express();
    const router = Router();

    defineRoute(router, {
      method: 'get',
      path: '/secure',
      auth: 'access',
      schemas: {
        response: {
          200: z.object({ message: z.string() }),
          401: z.object({ error: z.string() }),
        },
      },
      handler,
    });

    app.use(router);

    const res = await request(app).get('/secure');

    expect(res.status).toBe(401);
    expect(res.body).toEqual({ error: 'missing bearer token' });
    expect(handler).not.toHaveBeenCalled();
    expect(validateBearerToken).not.toHaveBeenCalled();
  });

  it('passes the declared auth type to bearer validation before running the handler', async () => {
    const { defineRoute } = await import('../../../src/lib/defineRoute.js');
    const { validateBearerToken } = await import('../../../src/services/sessionService.js');
    const app = express();
    const router = Router();

    (validateBearerToken as any).mockResolvedValue({
      user: { id: 'user-1', roles: ['user'] },
      sessionId: 'session-1',
    });

    defineRoute(router, {
      method: 'get',
      path: '/secure',
      auth: 'access',
      schemas: {
        response: {
          200: z.object({ message: z.string() }),
        },
      },
      handler: (req, res) => {
        res.status(200).json({
          message: req.user?.id ?? 'missing',
        });
      },
    });

    app.use(router);

    const res = await request(app).get('/secure').set('Authorization', 'Bearer access-token');

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ message: 'user-1' });
    expect(validateBearerToken).toHaveBeenCalledWith('access-token', 'access');
  });
});
