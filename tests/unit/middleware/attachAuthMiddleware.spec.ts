import { describe, it, expect, vi, beforeEach, afterAll } from 'vitest';

vi.unmock('../../../src/middleware/verifyBearerAuth');
vi.unmock('../../../src/middleware/verifyCookieAuth');
vi.unmock('../../../src/middleware/attachAuthMiddleware');

vi.mock('../../../src/middleware/verifyBearerAuth', () => ({
  verifyBearerAuth: () => vi.fn().mockResolvedValue('Bearer Auth User'),
}));

vi.mock('../../../src/middleware/verifyCookieAuth', () => ({
  verifyCookieAuth: vi.fn(),
}));

vi.mock('../../src/middleware/attachAuthMiddleware.js', () => ({
  attachAuthMiddleware: (v: string) => (req: any, _res: any, next: any) => {
    next();
  },
}));

import { attachAuthMiddleware } from '../../../src/middleware/attachAuthMiddleware';
import { verifyCookieAuth } from '../../../src/middleware/verifyCookieAuth';
import { verifyBearerAuth } from '../../../src/middleware/verifyBearerAuth';

describe('attachAuthMiddleware', () => {
  beforeEach(() => {
    vi.resetModules();
    delete process.env.AUTH_MODE;
  });

  afterAll(() => {
    vi.unstubAllEnvs();
  });
  it('defaults to cookie auth', async () => {
    attachAuthMiddleware();

    expect(verifyCookieAuth).toHaveBeenCalledWith('access');
  });

  it('uses ephemeral cookie', async () => {
    attachAuthMiddleware('ephemeral');

    expect(verifyCookieAuth).toHaveBeenCalledWith('ephemeral');
  });

  it('uses bearer in server mode', async () => {
    vi.stubEnv('AUTH_MODE', 'server');

    const { attachAuthMiddleware } = await import('../../../src/middleware/attachAuthMiddleware');
    const { verifyBearerAuth } = await import('../../../src/middleware/verifyBearerAuth');
    const res = attachAuthMiddleware();

    expect(res).toBe(verifyBearerAuth);
  });
});
