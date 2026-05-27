import { vi } from 'vitest';

export function buildCredential(overrides: any = {}) {
  return {
    id: 'cred-1',
    userId: 'user-1',
    friendlyName: 'My Device',
    transports: [],
    deviceType: 'singleDevice',
    backedup: false,
    backedUp: false,
    prfCapable: false,
    counter: 0,
    lastUsedAt: new Date(),
    platform: 'web',
    browser: 'chrome',
    deviceInfo: 'test',
    createdAt: new Date(),
    publicKey: 'key',
    update: vi.fn(),
    destroy: vi.fn(),
    ...overrides,
  };
}
