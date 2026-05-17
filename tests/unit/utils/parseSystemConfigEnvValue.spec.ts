import { describe, it, expect } from 'vitest';
import { parseSystemConfigEnvValue } from '../../../src/utils/parseEnvConfigs';

describe('parseSystemConfigEnvValue', () => {
  describe('array parsing', () => {
    it('parses comma-separated values', () => {
      const result = parseSystemConfigEnvValue('available_roles', 'user,admin,editor');

      expect(result).toEqual(['user', 'admin', 'editor']);
    });

    it('trims whitespace and filters empty values', () => {
      const result = parseSystemConfigEnvValue('origins', ' http://a.com , , http://b.com ');

      expect(result).toEqual(['http://a.com', 'http://b.com']);
    });

    it('parses login methods', () => {
      const result = parseSystemConfigEnvValue('login_methods', 'passkey, magic_link, email_otp');

      expect(result).toEqual(['passkey', 'magic_link', 'email_otp']);
    });
  });

  describe('number parsing', () => {
    it('parses rate_limit', () => {
      const result = parseSystemConfigEnvValue('rate_limit', '100');

      expect(result).toBe(100);
    });

    it('parses delay_after', () => {
      const result = parseSystemConfigEnvValue('delay_after', '50');

      expect(result).toBe(50);
    });

    it('returns NaN for invalid number', () => {
      const result = parseSystemConfigEnvValue('rate_limit', 'bad');

      expect(result).toBeNaN();
    });
  });

  describe('string passthrough', () => {
    it('returns access_token_ttl as-is', () => {
      const result = parseSystemConfigEnvValue('access_token_ttl', '15m');

      expect(result).toBe('15m');
    });

    it('returns app_name as-is', () => {
      const result = parseSystemConfigEnvValue('app_name', 'SeamlessAuth');

      expect(result).toBe('SeamlessAuth');
    });
  });

  describe('boolean parsing', () => {
    it('parses passkey_login_fallback_enabled', () => {
      expect(parseSystemConfigEnvValue('passkey_login_fallback_enabled', 'true')).toBe(true);
      expect(parseSystemConfigEnvValue('passkey_login_fallback_enabled', 'false')).toBe(false);
    });
  });

  describe('invalid key', () => {
    it('throws for unknown key', () => {
      expect(() => parseSystemConfigEnvValue('invalid_key' as any, 'value')).toThrow(
        'Unhandled system config key',
      );
    });
  });
});
