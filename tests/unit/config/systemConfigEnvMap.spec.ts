import { describe, expect, it } from 'vitest';

import { SYSTEM_CONFIG_ENV_MAP } from '../../../src/config/systemConfig.envMap.js';

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
      app_name: 'APP_NAME',
    });
  });
});
