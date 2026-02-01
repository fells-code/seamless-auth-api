/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
export interface RequiredSystemConfig {
  app_name: string;
  default_roles: string[];
  available_roles: string[];

  access_token_ttl: string;
  refresh_token_ttl: string;

  rate_limit: number;
  delay_after: number;

  rpid: string;
  origin: string[];
}

export const REQUIRED_SYSTEM_CONFIG_KEYS: {
  key: keyof RequiredSystemConfig;
  env: string;
}[] = [
  {
    key: 'default_roles',
    env: 'DEFAULT_ROLES',
  },
  {
    key: 'available_roles',
    env: 'AVAILABLE_ROLES',
  },
  {
    key: 'access_token_ttl',
    env: 'ACCESS_TOKEN_TTL',
  },
  {
    key: 'refresh_token_ttl',
    env: 'REFRESH_TOKEN_TTL',
  },
  {
    key: 'rate_limit',
    env: 'RATE_LIMIT',
  },
  {
    key: 'delay_after',
    env: 'DELAY_AFTER',
  },
  {
    key: 'rpid',
    env: 'RPID',
  },
  {
    key: 'origin',
    env: 'ORIGINS',
  },
  {
    key: 'app_name',
    env: 'APP_NAME',
  },
];
