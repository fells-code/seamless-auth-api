export function buildSystemConfig(overrides: any = {}) {
  return {
    app_name: 'SeamlessAuth',
    default_roles: ['user'],
    available_roles: ['user', 'admin'],
    access_token_ttl: '15m',
    refresh_token_ttl: '7d',
    rate_limit: 100,
    delay_after: 50,
    rpid: 'localhost',
    origins: ['http://localhost:5174'],
    ...overrides,
  };
}
