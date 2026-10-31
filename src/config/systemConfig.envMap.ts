/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

export const SYSTEM_CONFIG_ENV_MAP = {
  default_roles: 'DEFAULT_ROLES',
  available_roles: 'AVAILABLE_ROLES',
  login_methods: 'LOGIN_METHODS',
  oauth_providers: 'OAUTH_PROVIDERS',
  lockout_policy: 'LOCKOUT_POLICY',
  authenticator_policy: 'AUTHENTICATOR_POLICY',
  recovery_codes: 'RECOVERY_CODES',
  account_recovery: 'ACCOUNT_RECOVERY',
  passkey_login_fallback_enabled: 'PASSKEY_LOGIN_FALLBACK_ENABLED',
  prompt_passkey_enrollment: 'PROMPT_PASSKEY_ENROLLMENT',
  phishing_resistant_only: 'PHISHING_RESISTANT_ONLY',
  access_token_ttl: 'ACCESS_TOKEN_TTL',
  session_idle_ttl: 'SESSION_IDLE_TTL',
  max_concurrent_sessions: 'MAX_CONCURRENT_SESSIONS',
  refresh_token_ttl: 'REFRESH_TOKEN_TTL',
  rate_limit: 'RATE_LIMIT',
  delay_after: 'DELAY_AFTER',
  flow_rate_limits: 'FLOW_RATE_LIMITS',
  rpid: 'RPID',
  origins: 'ORIGINS',
  frontend_url: 'FRONTEND_URL',
  magic_link_redirect_uris: 'MAGIC_LINK_REDIRECT_URIS',
  app_name: 'APP_NAME',
  oidc_provider_enabled: 'OIDC_PROVIDER_ENABLED',
  oidc_issuer: 'OIDC_ISSUER',
  allow_client_secrets: 'OIDC_ALLOW_CLIENT_SECRETS',
  third_party_clients_enabled: 'OIDC_THIRD_PARTY_CLIENTS_ENABLED',
  hosted_ui: 'OIDC_HOSTED_UI',
} as const;
