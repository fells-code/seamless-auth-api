import { beforeEach, describe, expect, it, vi } from 'vitest';

import { getSystemConfig } from '../../../src/config/getSystemConfig.js';
import {
  MagicLinkRedirectNotAllowedError,
  resolveMagicLinkUrl,
} from '../../../src/services/magicLinkRedirect.js';

function configure(overrides: Record<string, unknown> = {}) {
  (getSystemConfig as ReturnType<typeof vi.fn>).mockResolvedValue({
    origins: ['http://localhost:5174'],
    ...overrides,
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  configure();
});

describe('resolveMagicLinkUrl', () => {
  describe('with no requested target', () => {
    it('keeps the tenant-wide destination', async () => {
      expect(await resolveMagicLinkUrl('tok')).toBe(
        'http://localhost:5174/verify-magiclink?token=tok',
      );
    });

    it('prefers frontend_url over the first origin', async () => {
      configure({
        origins: ['http://localhost:3000', 'http://localhost:5001'],
        frontend_url: 'http://localhost:5001',
      });

      expect(await resolveMagicLinkUrl('tok')).toBe(
        'http://localhost:5001/verify-magiclink?token=tok',
      );
    });
  });

  describe('with a requested target', () => {
    it('honours one whose origin is configured', async () => {
      const url = await resolveMagicLinkUrl('tok', 'http://localhost:5174/mobile/finish');

      expect(url).toBe('http://localhost:5174/mobile/finish?token=tok');
    });

    it('lets web and mobile clients reach different paths on one tenant', async () => {
      const web = await resolveMagicLinkUrl('tok', 'http://localhost:5174/verify-magiclink');
      const mobile = await resolveMagicLinkUrl('tok', 'http://localhost:5174/app/magic');

      expect(web).not.toBe(mobile);
      expect(mobile).toContain('/app/magic');
    });

    it('keeps a query the caller already put on the target', async () => {
      const url = await resolveMagicLinkUrl('tok', 'http://localhost:5174/finish?platform=ios');

      expect(url).toContain('platform=ios');
      expect(url).toContain('token=tok');
    });

    // Otherwise a caller could decide which token the client reads.
    it('replaces a token the caller supplied rather than appending a second', async () => {
      const url = await resolveMagicLinkUrl('real', 'http://localhost:5174/finish?token=attacker');

      expect(url).toBe('http://localhost:5174/finish?token=real');
    });

    it('refuses an origin that is not configured', async () => {
      await expect(resolveMagicLinkUrl('tok', 'https://evil.example/steal')).rejects.toBeInstanceOf(
        MagicLinkRedirectNotAllowedError,
      );
    });

    // A near-miss host is the whole point of matching on origin rather than prefix.
    it('refuses a host that merely starts with a configured one', async () => {
      await expect(
        resolveMagicLinkUrl('tok', 'http://localhost:5174.evil.example/steal'),
      ).rejects.toBeInstanceOf(MagicLinkRedirectNotAllowedError);
    });

    it('refuses a different port on a configured host', async () => {
      await expect(resolveMagicLinkUrl('tok', 'http://localhost:9999/x')).rejects.toBeInstanceOf(
        MagicLinkRedirectNotAllowedError,
      );
    });

    it('refuses a value that is not a URL', async () => {
      await expect(resolveMagicLinkUrl('tok', 'not-a-url')).rejects.toBeInstanceOf(
        MagicLinkRedirectNotAllowedError,
      );
    });
  });
});
