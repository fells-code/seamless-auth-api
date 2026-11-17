import { vi } from 'vitest';

const HOUR_MS = 60 * 60 * 1000;

/** Signed in a moment ago on a chain that began an hour ago, after the factory factors. */
export function buildSession(overrides: any = {}) {
  const chainStartedAt = new Date(Date.now() - HOUR_MS);

  return {
    id: 'session-1',
    createdAt: chainStartedAt,
    chainStartedAt,
    authTime: new Date(),
    parentSessionId: null,
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
    reload: vi.fn(),
    ...overrides,
  };
}

/** The current session after a step-up, which every `requireStepUp()` route looks up first. */
export function buildFreshStepUpSession(overrides: any = {}) {
  return buildSession({ stepUpVerifiedAt: new Date(), stepUpMethod: 'webauthn', ...overrides });
}
