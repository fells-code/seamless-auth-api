import { describe, expect, it } from 'vitest';

import { SYSTEM_CONFIG_ENV_MAP } from '../../../src/config/systemConfig.envMap.js';
import { SystemConfigSchema } from '../../../src/schemas/systemConfig.schema.js';
import { parseSystemConfigEnvValue } from '../../../src/utils/parseEnvConfigs.js';

describe('SYSTEM_CONFIG_ENV_MAP', () => {
  it('maps each config key to its uppercase environment variable', () => {
    for (const env of Object.values(SYSTEM_CONFIG_ENV_MAP)) {
      expect(env).toBe(env.toUpperCase());
    }
  });

  it('exposes the expected key-to-env pairs', () => {
    expect(SYSTEM_CONFIG_ENV_MAP).toEqual({
      default_roles: 'DEFAULT_ROLES',
      available_roles: 'AVAILABLE_ROLES',
      login_methods: 'LOGIN_METHODS',
      oauth_providers: 'OAUTH_PROVIDERS',
      lockout_policy: 'LOCKOUT_POLICY',
      authenticator_policy: 'AUTHENTICATOR_POLICY',
      passkey_login_fallback_enabled: 'PASSKEY_LOGIN_FALLBACK_ENABLED',
      access_token_ttl: 'ACCESS_TOKEN_TTL',
      refresh_token_ttl: 'REFRESH_TOKEN_TTL',
      session_idle_ttl: 'SESSION_IDLE_TTL',
      max_concurrent_sessions: 'MAX_CONCURRENT_SESSIONS',
      rate_limit: 'RATE_LIMIT',
      delay_after: 'DELAY_AFTER',
      rpid: 'RPID',
      origins: 'ORIGINS',
      frontend_url: 'FRONTEND_URL',
      magic_link_redirect_uris: 'MAGIC_LINK_REDIRECT_URIS',
      app_name: 'APP_NAME',
    });
  });

  // The map is what bootstrapSystemConfig iterates, so a key missing from it is one no
  // deployment can set declaratively. magic_link_redirect_uris was absent, which left
  // the only control over magic link destinations settable through the admin API alone.
  // Asserted against the schema so a key added upstream is caught here rather than by
  // an operator who cannot configure it.
  it('covers every key the config schema defines', () => {
    const mapped = Object.keys(SYSTEM_CONFIG_ENV_MAP);
    const missing = Object.keys(SystemConfigSchema.shape).filter((key) => !mapped.includes(key));

    expect(missing).toEqual([]);
  });

  // A key in the map with no branch in the parser reaches its `default` and throws
  // "Unhandled system config key" at boot. Whether a given value parses is a separate
  // question, and one bootstrapSystemConfig only asks when the variable is set.
  it('has a parser branch for every mapped key', () => {
    for (const key of Object.keys(SYSTEM_CONFIG_ENV_MAP)) {
      try {
        parseSystemConfigEnvValue(key as keyof typeof SYSTEM_CONFIG_ENV_MAP, '');
      } catch (error) {
        expect((error as Error).message).not.toContain('Unhandled system config key');
      }
    }
  });
});
