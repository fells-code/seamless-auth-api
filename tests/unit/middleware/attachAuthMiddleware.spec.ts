import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.unmock('../../../src/middleware/verifyBearerAuth');
vi.unmock('../../../src/middleware/attachAuthMiddleware');

vi.mock('../../../src/middleware/verifyBearerAuth', () => ({
  verifyBearerAuth: vi.fn((_req: any, _res: any, next: any) => next()),
}));

describe('attachAuthMiddleware', () => {
  beforeEach(() => {
    vi.resetModules();
  });

  it('defaults to access bearer auth', async () => {
    const { attachAuthMiddleware } = await import('../../../src/middleware/attachAuthMiddleware');
    const { verifyBearerAuth } = await import('../../../src/middleware/verifyBearerAuth');
    const middleware = attachAuthMiddleware();

    expect(middleware).toBe(verifyBearerAuth);
    expect(middleware.seamlessAuthType).toBe('access');
  });

  it('tracks ephemeral bearer auth for route metadata', async () => {
    const { attachAuthMiddleware } = await import('../../../src/middleware/attachAuthMiddleware');
    const middleware = attachAuthMiddleware('ephemeral');

    expect(middleware.seamlessAuthType).toBe('ephemeral');
    expect(typeof middleware).toBe('function');
  });

  it('always maps protected routes to bearer security', async () => {
    const { getSecuritySchemeName } = await import('../../../src/middleware/attachAuthMiddleware');

    expect(getSecuritySchemeName('access')).toBe('bearerAuth');
    expect(getSecuritySchemeName('ephemeral')).toBe('bearerAuth');
  });
});
