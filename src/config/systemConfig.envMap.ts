/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
export const SYSTEM_CONFIG_ENV_MAP = {
  default_roles: 'DEFAULT_ROLES',
  available_roles: 'AVAILABLE_ROLES',
  access_token_ttl: 'ACCESS_TOKEN_TTL',
  refresh_token_ttl: 'REFRESH_TOKEN_TTL',
  rate_limit: 'RATE_LIMIT',
  delay_after: 'DELAY_AFTER',
  rpid: 'RPID',
  origins: 'ORIGINS',
  app_name: 'APP_NAME',
} as const;
