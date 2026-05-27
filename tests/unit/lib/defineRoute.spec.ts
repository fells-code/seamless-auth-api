import { Router } from 'express';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { z } from 'zod';

vi.mock('../../../src/middleware/attachAuthMiddleware.js', () => ({
  attachAuthMiddleware: vi.fn((authType: 'access' | 'ephemeral' = 'access') =>
    Object.assign(vi.fn(), { seamlessAuthType: authType }),
  ),
  getSecuritySchemeName: vi.fn(() => 'bearerAuth'),
}));

vi.mock('../../../src/openapi/registry', () => ({
  registry: {
    registerPath: vi.fn(),
  },
}));

describe('defineRoute', () => {
  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();
  });

  it('adds bearer security when auth is inferred from access middleware', async () => {
    const { defineRoute } = await import('../../../src/lib/defineRoute');
    const { registry } = await import('../../../src/openapi/registry');
    const middleware = Object.assign(vi.fn(), { seamlessAuthType: 'access' as const });

    defineRoute(Router(), {
      method: 'get',
      path: '/secure',
      middleware: [middleware],
      schemas: {
        response: {
          200: z.object({
            message: z.string(),
          }),
        },
      },
      handler: vi.fn(),
    });

    expect(registry.registerPath).toHaveBeenCalledWith(
      expect.objectContaining({
        security: [{ bearerAuth: [] }],
      }),
    );
  });

  it('adds bearer security when auth is inferred from ephemeral middleware', async () => {
    const { defineRoute } = await import('../../../src/lib/defineRoute');
    const { registry } = await import('../../../src/openapi/registry');
    const middleware = Object.assign(vi.fn(), { seamlessAuthType: 'ephemeral' as const });

    defineRoute(Router(), {
      method: 'get',
      path: '/ephemeral',
      middleware: [middleware],
      schemas: {
        response: {
          200: z.object({
            message: z.string(),
          }),
        },
      },
      handler: vi.fn(),
    });

    expect(registry.registerPath).toHaveBeenCalledWith(
      expect.objectContaining({
        security: [{ bearerAuth: [] }],
      }),
    );
  });

  it('runs auth middleware before custom middleware when auth is declared on the route', async () => {
    const order: string[] = [];
    const { defineRoute } = await import('../../../src/lib/defineRoute');
    const { attachAuthMiddleware } =
      await import('../../../src/middleware/attachAuthMiddleware.js');

    (attachAuthMiddleware as any).mockImplementation((authType: 'access' | 'ephemeral') =>
      Object.assign(
        (_req: any, _res: any, next: () => void) => {
          order.push(`auth:${authType}`);
          next();
        },
        { seamlessAuthType: authType },
      ),
    );

    const router = Router();

    defineRoute(router, {
      method: 'get',
      path: '/ordered',
      auth: 'access',
      middleware: [
        (_req: any, _res: any, next: () => void) => {
          order.push('custom');
          next();
        },
      ],
      schemas: {
        response: {
          200: z.object({
            message: z.string(),
          }),
        },
      },
      handler: (_req, res) => {
        order.push('handler');
        res.status(200).json({ message: 'ok' });
      },
    });

    const layer = (router as any).stack.find((entry: any) => entry.route?.path === '/ordered');
    const handlers = layer.route.stack.map((entry: any) => entry.handle);
    const req = { params: {}, query: {}, body: {} };
    const json = vi.fn();
    const res = {
      statusCode: 200,
      status(code: number) {
        this.statusCode = code;
        return this;
      },
      json,
    };

    const run = async (index: number): Promise<void> => {
      const handler = handlers[index];

      if (!handler) {
        return;
      }

      await handler(req, res, () => run(index + 1));
    };

    await run(0);

    expect(order).toEqual(['auth:access', 'custom', 'handler']);
  });

  it('documents and validates a direct Zod response schema as HTTP 200', async () => {
    const { defineRoute } = await import('../../../src/lib/defineRoute');
    const { registry } = await import('../../../src/openapi/registry');
    const router = Router();

    defineRoute(router, {
      method: 'get',
      path: '/direct-schema',
      schemas: {
        response: z.object({
          message: z.string(),
        }),
      },
      handler: (_req, res) => {
        res.status(200).json({ message: 'ok', extra: 'removed' });
      },
    });

    expect(registry.registerPath).toHaveBeenCalledWith(
      expect.objectContaining({
        responses: expect.objectContaining({
          '200': expect.objectContaining({
            content: expect.objectContaining({
              'application/json': expect.objectContaining({
                schema: expect.any(Object),
              }),
            }),
          }),
        }),
      }),
    );

    const layer = (router as any).stack.find(
      (entry: any) => entry.route?.path === '/direct-schema',
    );
    const handlers = layer.route.stack.map((entry: any) => entry.handle);
    const req = { params: {}, query: {}, body: {} };
    const json = vi.fn();
    const res = {
      statusCode: 200,
      status(code: number) {
        this.statusCode = code;
        return this;
      },
      json,
    };

    const run = async (index: number): Promise<void> => {
      const handler = handlers[index];

      if (!handler) {
        return;
      }

      await handler(req, res, () => run(index + 1));
    };

    await run(0);

    expect(json).toHaveBeenCalledWith({ message: 'ok' });
  });
});
