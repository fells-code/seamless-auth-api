import { Router } from 'express';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { z } from 'zod';

vi.mock('../../../src/middleware/attachAuthMiddleware.js', () => ({
  attachAuthMiddleware: vi.fn((cookieType: 'access' | 'ephemeral' = 'access') =>
    Object.assign(vi.fn(), { seamlessAuthType: cookieType }),
  ),
  getSecuritySchemeName: vi.fn((cookieType: 'access' | 'ephemeral') => {
    if (process.env.AUTH_MODE === 'server') {
      return 'bearerAuth';
    }

    return cookieType === 'ephemeral' ? 'ephemeralCookieAuth' : 'accessCookieAuth';
  }),
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
    delete process.env.AUTH_MODE;
  });

  it('adds access cookie security when auth is inferred from middleware in web mode', async () => {
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
        security: [{ accessCookieAuth: [] }],
      }),
    );
  });

  it('adds ephemeral cookie security when auth is inferred from middleware in web mode', async () => {
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
        security: [{ ephemeralCookieAuth: [] }],
      }),
    );
  });

  it('adds bearer security in server mode even when auth comes from middleware', async () => {
    process.env.AUTH_MODE = 'server';

    const { defineRoute } = await import('../../../src/lib/defineRoute');
    const { registry } = await import('../../../src/openapi/registry');
    const middleware = Object.assign(vi.fn(), { seamlessAuthType: 'access' as const });

    defineRoute(Router(), {
      method: 'get',
      path: '/server-secure',
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
});
