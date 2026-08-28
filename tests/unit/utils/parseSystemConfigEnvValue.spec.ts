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

    it('parses default_roles', () => {
      expect(parseSystemConfigEnvValue('default_roles', 'user,guest')).toEqual(['user', 'guest']);
    });
  });

  describe('remaining string passthrough keys', () => {
    it('returns refresh_token_ttl as-is', () => {
      expect(parseSystemConfigEnvValue('refresh_token_ttl', '7d')).toBe('7d');
    });

    it('returns rpid as-is', () => {
      expect(parseSystemConfigEnvValue('rpid', 'example.com')).toBe('example.com');
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

    it('returns frontend_url as a single string, not an array', () => {
      const result = parseSystemConfigEnvValue('frontend_url', 'http://localhost:5173');

      expect(result).toBe('http://localhost:5173');
    });
  });

  describe('boolean parsing', () => {
    it('parses passkey_login_fallback_enabled', () => {
      expect(parseSystemConfigEnvValue('passkey_login_fallback_enabled', 'true')).toBe(true);
      expect(parseSystemConfigEnvValue('passkey_login_fallback_enabled', 'false')).toBe(false);
    });
  });

  describe('oauth_providers parsing', () => {
    it('applies per-provider schema defaults (e.g. subjectJsonPath)', () => {
      const raw = JSON.stringify([
        {
          id: 'mock',
          name: 'Mock',
          clientId: 'client',
          clientSecretEnv: 'MOCK_SECRET',
          authorizationUrl: 'https://idp.test/authorize',
          tokenUrl: 'https://idp.test/token',
          userInfoUrl: 'https://idp.test/userinfo',
        },
      ]);

      const result = parseSystemConfigEnvValue('oauth_providers', raw) as Array<
        Record<string, unknown>
      >;

      expect(result[0]).toMatchObject({
        enabled: true,
        subjectJsonPath: 'sub',
        emailJsonPath: 'email',
        emailVerifiedJsonPath: 'email_verified',
        scopes: [],
        allowSignup: true,
        accountLinking: 'email',
      });
    });

    it('throws on an invalid provider entry', () => {
      expect(() => parseSystemConfigEnvValue('oauth_providers', '[{"id":"x"}]')).toThrow();
    });
  });

  describe('lockout_policy parsing', () => {
    it('parses the lockout policy JSON object', () => {
      const raw = JSON.stringify({
        enabled: true,
        maxFailures: 5,
        windowSeconds: 60,
        lockoutSeconds: 120,
      });

      expect(parseSystemConfigEnvValue('lockout_policy', raw)).toEqual({
        enabled: true,
        maxFailures: 5,
        windowSeconds: 60,
        lockoutSeconds: 120,
      });
    });
  });

  describe('authenticator_policy parsing', () => {
    it('parses the authenticator policy JSON object', () => {
      const raw = JSON.stringify({ attachment: 'cross-platform' });

      expect(parseSystemConfigEnvValue('authenticator_policy', raw)).toEqual({
        attachment: 'cross-platform',
      });
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
