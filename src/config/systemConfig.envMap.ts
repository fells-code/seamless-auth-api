/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

export const SYSTEM_CONFIG_ENV_MAP = {
  default_roles: 'DEFAULT_ROLES',
  available_roles: 'AVAILABLE_ROLES',
  login_methods: 'LOGIN_METHODS',
  oauth_providers: 'OAUTH_PROVIDERS',
  lockout_policy: 'LOCKOUT_POLICY',
  authenticator_policy: 'AUTHENTICATOR_POLICY',
  passkey_login_fallback_enabled: 'PASSKEY_LOGIN_FALLBACK_ENABLED',
  access_token_ttl: 'ACCESS_TOKEN_TTL',
  refresh_token_ttl: 'REFRESH_TOKEN_TTL',
  rate_limit: 'RATE_LIMIT',
  delay_after: 'DELAY_AFTER',
  rpid: 'RPID',
  origins: 'ORIGINS',
  frontend_url: 'FRONTEND_URL',
  app_name: 'APP_NAME',
} as const;
