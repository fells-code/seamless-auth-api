function buildEvent(overrides: any = {}) {
  return {
    type: 'login_failed',
    ip_address: '127.0.0.1',
    user_agent: 'agent',
    get: (key: string) => overrides[key],
    ...overrides,
  };
}
