import { describe, it, expect } from 'vitest';

import { REQUIRED_SYSTEM_CONFIG_KEYS } from '../../../src/config/requiredSystemConfig';

describe('REQUIRED_SYSTEM_CONFIG_KEYS', () => {
  it('contains all required keys', () => {
    const keys = REQUIRED_SYSTEM_CONFIG_KEYS.map((k) => k.key);

    expect(keys).toEqual([
      'default_roles',
      'available_roles',
      'access_token_ttl',
      'refresh_token_ttl',
      'rate_limit',
      'delay_after',
      'rpid',
      'origin',
      'app_name',
    ]);
  });

  it('maps keys to correct env variables', () => {
    const map = Object.fromEntries(REQUIRED_SYSTEM_CONFIG_KEYS.map((k) => [k.key, k.env]));

    expect(map).toEqual({
      default_roles: 'DEFAULT_ROLES',
      available_roles: 'AVAILABLE_ROLES',
      access_token_ttl: 'ACCESS_TOKEN_TTL',
      refresh_token_ttl: 'REFRESH_TOKEN_TTL',
      rate_limit: 'RATE_LIMIT',
      delay_after: 'DELAY_AFTER',
      rpid: 'RPID',
      origin: 'ORIGINS',
      app_name: 'APP_NAME',
    });
  });

  it('does not contain duplicate keys', () => {
    const keys = REQUIRED_SYSTEM_CONFIG_KEYS.map((k) => k.key);

    const unique = new Set(keys);

    expect(unique.size).toBe(keys.length);
  });

  it('does not contain duplicate env values', () => {
    const envs = REQUIRED_SYSTEM_CONFIG_KEYS.map((k) => k.env);

    const unique = new Set(envs);

    expect(unique.size).toBe(envs.length);
  });

  it('all env values are uppercase', () => {
    for (const { env } of REQUIRED_SYSTEM_CONFIG_KEYS) {
      expect(env).toBe(env.toUpperCase());
    }
  });
});
