export function buildSession(overrides: any = {}) {
  return {
    id: 'session-1',
    deviceName: 'MacBook',
    ipAddress: '127.0.0.1',
    userAgent: 'agent',
    current: true,
    lastUsedAt: new Date().toDateString(),
    expiresAt: new Date(Date.now() + 100000).toDateString(),
    revokedAt: null,
    ...overrides,
  };
}
