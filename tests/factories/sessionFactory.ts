export function buildSession(overrides: any = {}) {
  return {
    id: 'session-1',
    deviceName: 'MacBook',
    ipAddress: '127.0.0.1',
    userAgent: 'agent',
    lastUsedAt: new Date(),
    expiresAt: new Date(Date.now() + 100000),
    revokedAt: null,
    ...overrides,
  };
}
