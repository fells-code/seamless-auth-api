import { describe, it, expect, vi, beforeEach, afterAll } from 'vitest';

vi.unmock('../../../src/middleware/verifyBearerAuth');
vi.unmock('../../../src/middleware/verifyCookieAuth');
vi.unmock('../../../src/middleware/attachAuthMiddleware');

vi.mock('../../../src/middleware/verifyBearerAuth', () => ({
  verifyBearerAuth: vi.fn((_req: any, _res: any, next: any) => next()),
}));

vi.mock('../../../src/middleware/verifyCookieAuth', () => ({
  verifyCookieAuth: vi.fn(() => vi.fn((_req: any, _res: any, next: any) => next())),
}));

describe('attachAuthMiddleware', () => {
  beforeEach(() => {
    vi.resetModules();
    delete process.env.AUTH_MODE;
  });

  afterAll(() => {
    vi.unstubAllEnvs();
  });
  it('defaults to cookie auth', async () => {
    const { attachAuthMiddleware } = await import('../../../src/middleware/attachAuthMiddleware');
    const middleware = attachAuthMiddleware();

    expect(middleware.seamlessAuthType).toBe('access');
    expect(typeof middleware).toBe('function');
  });

  it('uses ephemeral cookie', async () => {
    const { attachAuthMiddleware } = await import('../../../src/middleware/attachAuthMiddleware');
    const middleware = attachAuthMiddleware('ephemeral');

    expect(middleware.seamlessAuthType).toBe('ephemeral');
    expect(typeof middleware).toBe('function');
  });

  it('uses bearer in server mode', async () => {
    vi.stubEnv('AUTH_MODE', 'server');

    const { attachAuthMiddleware } = await import('../../../src/middleware/attachAuthMiddleware');
    const { verifyBearerAuth } = await import('../../../src/middleware/verifyBearerAuth');
    const res = attachAuthMiddleware();

    expect(res).toBe(verifyBearerAuth);
  });
});
