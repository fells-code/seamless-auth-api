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
    console.log(process.env.AUTH_MODE);

    const { attachAuthMiddleware } = await import('../../../src/middleware/attachAuthMiddleware');
    const { verifyBearerAuth } = await import('../../../src/middleware/verifyBearerAuth');

    console.log(process.env.AUTH_MODE);
    const res = attachAuthMiddleware();

    console.log(res);

    expect(res).toBe(verifyBearerAuth);
  });
});
