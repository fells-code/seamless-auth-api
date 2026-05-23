export function buildSystemConfig(overrides: any = {}) {
  return {
    app_name: 'SeamlessAuth',
    default_roles: ['user'],
    available_roles: ['user', 'admin'],
    login_methods: ['passkey', 'magic_link'],
    oauth_providers: [],
    passkey_login_fallback_enabled: true,
    access_token_ttl: '15m',
    refresh_token_ttl: '7d',
    rate_limit: 100,
    delay_after: 50,
    rpid: 'localhost',
    origins: ['http://localhost:5174'],
    ...overrides,
  };
}
