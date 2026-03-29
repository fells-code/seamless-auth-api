import { vi } from 'vitest';

vi.unmock('../../../src/lib/cookie');
vi.mock('../../../src/config/getSystemConfig', () => ({
  getSystemConfig: vi.fn(),
}));

function buildRes() {
  return {
    cookie: vi.fn(),
    clearCookie: vi.fn(),
  } as any;
}

import { describe, it, expect, beforeEach } from 'vitest';
import { setAuthCookies, clearAuthCookies } from '../../../src/lib/cookie';
import { getSystemConfig } from '../../../src/config/getSystemConfig';

describe('cookie utils', () => {
  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();
    delete process.env.NODE_ENV;
  });

  describe('setAuthCookies', () => {
    it('sets access token cookie', async () => {
      const res = buildRes();

      (getSystemConfig as any).mockResolvedValue({
        access_token_ttl: '15m',
      });

      await setAuthCookies(res, { accessToken: 'access' });

      expect(res.cookie).toHaveBeenCalledWith(
        'seamless_access',
        'access',
        expect.objectContaining({
          httpOnly: true,
          path: '/',
        }),
      );
    });

    it('sets refresh token cookie', async () => {
      const res = buildRes();

      (getSystemConfig as any).mockResolvedValue({
        refresh_token_ttl: '1h',
      });

      await setAuthCookies(res, { refreshToken: 'refresh' });

      expect(res.cookie).toHaveBeenCalledWith(
        'seamless_refresh',
        'refresh',
        expect.objectContaining({
          httpOnly: true,
        }),
      );
    });

    it('sets ephemeral token cookie', async () => {
      const res = buildRes();

      await setAuthCookies(res, { ephemeralToken: 'temp' });

      expect(res.cookie).toHaveBeenCalledWith(
        'seamless_ephemeral',
        'temp',
        expect.objectContaining({
          httpOnly: true,
          maxAge: 5 * 60 * 1000,
        }),
      );
    });

    it('sets secure + sameSite in production', async () => {
      process.env.NODE_ENV = 'production';

      const res = buildRes();

      (getSystemConfig as any).mockResolvedValue({
        access_token_ttl: '15m',
      });

      await setAuthCookies(res, { accessToken: 'access' });

      expect(res.cookie).toHaveBeenCalledWith(
        'seamless_access',
        'access',
        expect.objectContaining({
          secure: true,
          sameSite: 'none',
        }),
      );
    });

    it('uses default TTL when missing config', async () => {
      const res = buildRes();

      (getSystemConfig as any).mockResolvedValue({});

      await setAuthCookies(res, { accessToken: 'access' });

      expect(res.cookie).toHaveBeenCalled();
    });
  });

  describe('clearAuthCookies', () => {
    it('clears all cookies', () => {
      const res = buildRes();

      clearAuthCookies(res);

      expect(res.clearCookie).toHaveBeenCalledTimes(3);
      expect(res.clearCookie).toHaveBeenCalledWith(
        'seamless_access',
        expect.objectContaining({ httpOnly: true }),
      );
      expect(res.clearCookie).toHaveBeenCalledWith(
        'seamless_refresh',
        expect.objectContaining({ httpOnly: true }),
      );
      expect(res.clearCookie).toHaveBeenCalledWith(
        'seamless_ephemeral',
        expect.objectContaining({ httpOnly: true }),
      );
    });

    it('uses secure flag in production', () => {
      process.env.NODE_ENV = 'production';

      const res = buildRes();

      clearAuthCookies(res);

      expect(res.clearCookie).toHaveBeenCalledWith(
        'seamless_access',
        expect.objectContaining({ secure: true }),
      );
    });
  });
});
