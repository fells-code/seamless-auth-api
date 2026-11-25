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
    it('keeps the tenant-wide destination, with the code in the fragment', async () => {
      expect(await resolveMagicLinkUrl('tok', 'cod')).toBe(
        'http://localhost:5174/verify-magiclink?token=tok#code=cod',
      );
    });

    it('prefers frontend_url over the first origin', async () => {
      configure({
        origins: ['http://localhost:3000', 'http://localhost:5001'],
        frontend_url: 'http://localhost:5001',
      });

      expect(await resolveMagicLinkUrl('tok', 'cod')).toBe(
        'http://localhost:5001/verify-magiclink?token=tok#code=cod',
      );
    });

    it('never puts the code in the query string', async () => {
      const url = new URL(await resolveMagicLinkUrl('tok', 'cod'));

      expect(url.searchParams.has('code')).toBe(false);
      expect(url.search).not.toContain('cod');
    });
  });

  // With no allowlist, the only target is the verify page the SDKs and adapters land on.
  // Matching on origin alone let a link land on any page of the site, including one that
  // forwards its URL to a third party.
  describe('with an empty magic_link_redirect_uris', () => {
    it('honours the verify page on a configured origin', async () => {
      expect(
        await resolveMagicLinkUrl('tok', 'cod', 'http://localhost:5174/verify-magiclink'),
      ).toBe('http://localhost:5174/verify-magiclink?token=tok#code=cod');
    });

    it('honours the verify page on any configured origin and on frontend_url', async () => {
      configure({
        origins: ['http://localhost:5174', 'https://app.example'],
        frontend_url: 'https://www.example/',
      });

      await expect(
        resolveMagicLinkUrl('tok', 'cod', 'https://app.example/verify-magiclink'),
      ).resolves.toContain('https://app.example/verify-magiclink?token=tok');
      await expect(
        resolveMagicLinkUrl('tok', 'cod', 'https://www.example/verify-magiclink'),
      ).resolves.toContain('https://www.example/verify-magiclink?token=tok');
    });

    it('refuses another path on a configured origin', async () => {
      await expect(
        resolveMagicLinkUrl('tok', 'cod', 'http://localhost:5174/mobile/finish'),
      ).rejects.toBeInstanceOf(MagicLinkRedirectNotAllowedError);
    });

    it('refuses the verify page carrying a query of its own', async () => {
      await expect(
        resolveMagicLinkUrl('tok', 'cod', 'http://localhost:5174/verify-magiclink?next=/x'),
      ).rejects.toBeInstanceOf(MagicLinkRedirectNotAllowedError);
    });

    it('refuses a path that merely starts with the verify page', async () => {
      await expect(
        resolveMagicLinkUrl('tok', 'cod', 'http://localhost:5174/verify-magiclink/../open'),
      ).rejects.toBeInstanceOf(MagicLinkRedirectNotAllowedError);
    });

    it('refuses an origin that is not configured', async () => {
      await expect(
        resolveMagicLinkUrl('tok', 'cod', 'https://evil.example/verify-magiclink'),
      ).rejects.toBeInstanceOf(MagicLinkRedirectNotAllowedError);
    });

    it('refuses a host that merely starts with a configured one', async () => {
      await expect(
        resolveMagicLinkUrl('tok', 'cod', 'http://localhost:5174.evil.example/verify-magiclink'),
      ).rejects.toBeInstanceOf(MagicLinkRedirectNotAllowedError);
    });

    it('refuses a different port on a configured host', async () => {
      await expect(
        resolveMagicLinkUrl('tok', 'cod', 'http://localhost:9999/verify-magiclink'),
      ).rejects.toBeInstanceOf(MagicLinkRedirectNotAllowedError);
    });

    it('refuses a value that is not a URL', async () => {
      await expect(resolveMagicLinkUrl('tok', 'cod', 'not-a-url')).rejects.toBeInstanceOf(
        MagicLinkRedirectNotAllowedError,
      );
    });
  });

  describe('with magic_link_redirect_uris configured', () => {
    it('allows a custom scheme that is listed exactly', async () => {
      configure({ magic_link_redirect_uris: ['myapp://auth'] });

      expect(await resolveMagicLinkUrl('tok', 'cod', 'myapp://auth')).toBe(
        'myapp://auth?token=tok#code=cod',
      );
    });

    it('lets web and mobile clients reach different listed targets', async () => {
      configure({
        magic_link_redirect_uris: [
          'http://localhost:5174/verify-magiclink',
          'http://localhost:5174/app/magic',
        ],
      });

      const web = await resolveMagicLinkUrl('tok', 'cod', 'http://localhost:5174/verify-magiclink');
      const mobile = await resolveMagicLinkUrl('tok', 'cod', 'http://localhost:5174/app/magic');

      expect(web).not.toBe(mobile);
      expect(mobile).toContain('/app/magic');
    });

    it('keeps a query a listed target carries', async () => {
      configure({ magic_link_redirect_uris: ['http://localhost:5174/finish?platform=ios'] });

      const url = await resolveMagicLinkUrl(
        'tok',
        'cod',
        'http://localhost:5174/finish?platform=ios',
      );

      expect(url).toContain('platform=ios');
      expect(url).toContain('token=tok');
    });

    // Otherwise a caller could decide which token or code the client reads.
    it('replaces a token and fragment the target supplied rather than adding a second', async () => {
      configure({
        magic_link_redirect_uris: ['http://localhost:5174/finish?token=attacker#code=attacker'],
      });

      const url = await resolveMagicLinkUrl(
        'real',
        'cod',
        'http://localhost:5174/finish?token=attacker#code=attacker',
      );

      expect(url).toBe('http://localhost:5174/finish?token=real#code=cod');
    });

    it('refuses a target that is not on the list, even the default verify page', async () => {
      configure({ magic_link_redirect_uris: ['myapp://auth'] });

      await expect(
        resolveMagicLinkUrl('tok', 'cod', 'http://localhost:5174/verify-magiclink'),
      ).rejects.toBeInstanceOf(MagicLinkRedirectNotAllowedError);
    });
  });
});
