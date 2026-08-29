import { vi } from 'vitest';

/**
 * A live challenge row, as `consumeChallenge` would find it.
 *
 * `update` is a spy so a test can assert the challenge was actually spent,
 * which is the property the store exists to guarantee.
 */
export function buildWebAuthnChallenge(overrides: Record<string, unknown> = {}) {
  return {
    id: 'challenge-1',
    userId: 'user-1',
    purpose: 'authentication',
    challenge: 'challenge',
    context: null,
    expiresAt: new Date(Date.now() + 300_000),
    consumedAt: null,
    update: vi.fn(),
    ...overrides,
  } as any;
}
