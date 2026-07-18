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

  it('forwards the deprecated flag to the OpenAPI registration', async () => {
    const { defineRoute } = await import('../../../src/lib/defineRoute');
    const { registry } = await import('../../../src/openapi/registry');

    defineRoute(Router(), {
      method: 'get',
      path: '/legacy',
      deprecated: true,
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
        deprecated: true,
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

  it('documents a default 200 Success response when no response schema is provided', async () => {
    const { defineRoute } = await import('../../../src/lib/defineRoute');
    const { registry } = await import('../../../src/openapi/registry');
    const router = Router();

    defineRoute(router, {
      method: 'get',
      path: '/no-response-schema',
      handler: (_req, res) => {
        res.status(200).json({ anything: 'passes-through' });
      },
    });

    expect(registry.registerPath).toHaveBeenCalledWith(
      expect.objectContaining({
        responses: { '200': { description: 'Success' } },
      }),
    );

    const layer = (router as any).stack.find(
      (entry: any) => entry.route?.path === '/no-response-schema',
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

    expect(json).toHaveBeenCalledWith({ anything: 'passes-through' });
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

  async function runRoute(router: Router, path: string, res: any) {
    const layer = (router as any).stack.find((entry: any) => entry.route?.path === path);
    const handlers = layer.route.stack.map((entry: any) => entry.handle);
    const req = { params: {}, query: {}, body: {} };

    const errors: unknown[] = [];
    const run = async (index: number): Promise<void> => {
      const handler = handlers[index];

      if (!handler) {
        return;
      }

      await handler(req, res, (err?: unknown) => {
        if (err) {
          errors.push(err);
          return;
        }

        return run(index + 1);
      });
    };

    await run(0);

    return errors;
  }

  function makeRes(statusCode = 200) {
    const json = vi.fn();
    const res = {
      statusCode,
      status(code: number) {
        this.statusCode = code;
        return this;
      },
      json,
    };

    return { res, json };
  }

  it('passes response data through untouched when no schema matches the status code', async () => {
    const { defineRoute } = await import('../../../src/lib/defineRoute');
    const router = Router();

    defineRoute(router, {
      method: 'get',
      path: '/status-map',
      schemas: {
        response: {
          200: z.object({ message: z.string() }),
        },
      },
      handler: (_req, res) => {
        res.status(404).json({ error: 'not found' });
      },
    });

    const { res, json } = makeRes();
    await runRoute(router, '/status-map', res);

    expect(json).toHaveBeenCalledWith({ error: 'not found' });
  });

  it('returns a validation error body when the response fails its schema', async () => {
    const { defineRoute } = await import('../../../src/lib/defineRoute');
    const router = Router();

    defineRoute(router, {
      method: 'get',
      path: '/bad-response',
      schemas: {
        response: z.object({ message: z.string() }),
      },
      handler: (_req, res) => {
        res.status(200).json({ message: 123 });
      },
    });

    const { res, json } = makeRes();
    await runRoute(router, '/bad-response', res);

    expect(json).toHaveBeenCalledWith(
      expect.objectContaining({
        error: 'Response validation failed',
        issues: expect.any(Array),
      }),
    );
  });

  it('forwards handler errors to next', async () => {
    const { defineRoute } = await import('../../../src/lib/defineRoute');
    const router = Router();
    const failure = new Error('handler boom');

    defineRoute(router, {
      method: 'get',
      path: '/throws',
      schemas: {
        response: z.object({ message: z.string() }),
      },
      handler: () => {
        throw failure;
      },
    });

    const { res } = makeRes();
    const errors = await runRoute(router, '/throws', res);

    expect(errors).toEqual([failure]);
  });

  it('registers without security when middleware carries no auth type', async () => {
    const { defineRoute } = await import('../../../src/lib/defineRoute');
    const { registry } = await import('../../../src/openapi/registry');

    defineRoute(Router(), {
      method: 'get',
      path: '/no-auth-middleware',
      middleware: [vi.fn()],
      schemas: {
        response: z.object({ message: z.string() }),
      },
      handler: vi.fn(),
    });

    expect(registry.registerPath).toHaveBeenCalledWith(
      expect.objectContaining({ security: undefined }),
    );
  });

  it('defaults an unset response status to 200 when selecting the response schema', async () => {
    const { defineRoute } = await import('../../../src/lib/defineRoute');
    const router = Router();

    defineRoute(router, {
      method: 'get',
      path: '/status-default',
      schemas: {
        response: {
          200: z.object({ message: z.string() }),
        },
      },
      handler: (_req, res) => {
        res.json({ message: 'ok', extra: 'removed' });
      },
    });

    const layer = (router as any).stack.find(
      (entry: any) => entry.route?.path === '/status-default',
    );
    const handlers = layer.route.stack.map((entry: any) => entry.handle);
    const req = { params: {}, query: {}, body: {} };
    const json = vi.fn();
    const res = { statusCode: 0, json };

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

  it('surfaces the raw error when response validation throws a non-Zod error', async () => {
    const { defineRoute } = await import('../../../src/lib/defineRoute');
    const router = Router();
    const failure = new Error('non-zod failure');
    const response = {
      safeParse: () => ({ success: true }),
      parse: () => {
        throw failure;
      },
    };

    defineRoute(router, {
      method: 'get',
      path: '/non-zod-response',
      schemas: {
        response: response as any,
      },
      handler: (_req, res) => {
        res.status(200).json({ message: 'ok' });
      },
    });

    const { res, json } = makeRes();
    await runRoute(router, '/non-zod-response', res);

    expect(json).toHaveBeenCalledWith({
      error: 'Response validation failed',
      issues: failure,
    });
  });

  it('parses and replaces params and query when their schemas are provided', async () => {
    const { defineRoute } = await import('../../../src/lib/defineRoute');
    const router = Router();

    defineRoute(router, {
      method: 'get',
      path: '/parsed/:id',
      schemas: {
        params: z.object({ id: z.string() }),
        query: z.object({ page: z.coerce.number() }),
      },
      handler: (req, res) => {
        res.status(200).json({ id: req.params.id, page: req.query.page });
      },
    });

    const layer = (router as any).stack.find((entry: any) => entry.route?.path === '/parsed/:id');
    const handlers = layer.route.stack.map((entry: any) => entry.handle);
    const req: any = { params: { id: 'abc' }, query: { page: '2' }, body: {} };
    const { res, json } = makeRes();

    const run = async (index: number): Promise<void> => {
      const handler = handlers[index];
      if (!handler) {
        return;
      }
      await handler(req, res, () => run(index + 1));
    };

    await run(0);

    expect(req.params).toEqual({ id: 'abc' });
    expect(req.query).toEqual({ page: 2 });
    expect(json).toHaveBeenCalledWith({ id: 'abc', page: 2 });
  });

  it('rejects requests whose body fails schema validation with a 400', async () => {
    const { defineRoute } = await import('../../../src/lib/defineRoute');
    const router = Router();

    defineRoute(router, {
      method: 'post',
      path: '/validated-body',
      schemas: {
        body: z.object({ name: z.string() }),
      },
      handler: (_req, res) => {
        res.status(200).json({ ok: true });
      },
    });

    const layer = (router as any).stack.find(
      (entry: any) => entry.route?.path === '/validated-body',
    );
    const handlers = layer.route.stack.map((entry: any) => entry.handle);
    const req = { params: {}, query: {}, body: { name: 123 } };
    const { res, json } = makeRes();

    await handlers[0](req, res, vi.fn());

    expect(res.statusCode).toBe(400);
    expect(json).toHaveBeenCalled();
  });
});
