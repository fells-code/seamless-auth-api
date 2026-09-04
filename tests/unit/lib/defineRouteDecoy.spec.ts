import { Router } from 'express';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { z } from 'zod';

vi.mock('../../../src/openapi/registry', () => ({
  registry: { registerPath: vi.fn() },
}));

const schemas = {
  response: {
    200: z.object({ message: z.string() }),
  },
};

beforeEach(() => {
  vi.clearAllMocks();
});

describe('defineRoute decoy dispatch', () => {
  it('refuses to register an ephemeral route with no decoy responder', async () => {
    const { defineRoute } = await import('../../../src/lib/defineRoute');

    // The failure this guards against is silent at runtime and invisible in a diff: a
    // new ephemeral endpoint that answers differently for a decoy hands the enumeration
    // oracle back, one request past /login.
    expect(() =>
      defineRoute(Router(), {
        method: 'get',
        path: '/forgot-the-decoy',
        auth: 'ephemeral',
        schemas,
        handler: vi.fn(),
      }),
    ).toThrow(/declares no decoy responder/);
  });

  it('registers an ephemeral route that declares one', async () => {
    const { defineRoute } = await import('../../../src/lib/defineRoute');

    expect(() =>
      defineRoute(Router(), {
        method: 'get',
        path: '/has-a-decoy',
        auth: 'ephemeral',
        schemas,
        handler: vi.fn(),
        decoy: vi.fn(),
      }),
    ).not.toThrow();
  });

  it('leaves routes that take no ephemeral token alone', async () => {
    const { defineRoute } = await import('../../../src/lib/defineRoute');

    expect(() =>
      defineRoute(Router(), {
        method: 'get',
        path: '/access-only',
        auth: 'access',
        schemas,
        handler: vi.fn(),
      }),
    ).not.toThrow();
  });

  it('sends a decoy request to the decoy responder and not the handler', async () => {
    const { defineRoute } = await import('../../../src/lib/defineRoute');
    const router = Router();
    const handler = vi.fn();
    const decoy = vi.fn((_req: any, res: any) => res.json({ message: 'decoy' }));

    defineRoute(router, {
      method: 'get',
      path: '/thing',
      auth: 'ephemeral',
      schemas,
      handler,
      decoy,
    });

    const stack = (router as any).stack.at(-1).route.stack;
    const wrapped = stack.at(-1).handle;
    const res = { json: vi.fn(), statusCode: 200 };

    await wrapped({ decoy: true } as any, res as any, vi.fn());

    // This is the invariant that makes the stand-in principal safe to shape like a
    // User: no controller, and so no write, ever sees it.
    expect(handler).not.toHaveBeenCalled();
    expect(decoy).toHaveBeenCalled();
  });

  it('sends an ordinary request to the handler', async () => {
    const { defineRoute } = await import('../../../src/lib/defineRoute');
    const router = Router();
    const handler = vi.fn((_req: any, res: any) => res.json({ message: 'real' }));
    const decoy = vi.fn();

    defineRoute(router, {
      method: 'get',
      path: '/thing',
      auth: 'ephemeral',
      schemas,
      handler,
      decoy,
    });

    const stack = (router as any).stack.at(-1).route.stack;
    const wrapped = stack.at(-1).handle;
    const res = { json: vi.fn(), statusCode: 200 };

    await wrapped({} as any, res as any, vi.fn());

    expect(handler).toHaveBeenCalled();
    expect(decoy).not.toHaveBeenCalled();
  });
});
