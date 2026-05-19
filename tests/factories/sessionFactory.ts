import { vi } from 'vitest';

export function buildSession(overrides: any = {}) {
  return {
    id: 'session-1',
    deviceName: 'MacBook',
    ipAddress: '127.0.0.1',
    userAgent: 'agent',
    current: true,
    lastUsedAt: new Date(),
    expiresAt: new Date(Date.now() + 100000),
    revokedAt: null,
    update: vi.fn().mockImplementation(function update(this: any, values: any) {
      Object.assign(this, values);
      return Promise.resolve(this);
    }),
    save: vi.fn(),
    ...overrides,
  };
}
