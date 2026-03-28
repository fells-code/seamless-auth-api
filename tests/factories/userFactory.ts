import { vi } from 'vitest';

export let testGuid = 'c6e39f68-a09d-49dd-86b4-eab2c1e5de52';

export function buildUser(overrides: Partial<any> = {}) {
  return {
    id: testGuid,
    email: 'test@example.com',
    phone: '+14155552671',
    roles: ['user'],
    challenge: 'challenge',
    createdAt: Date.now(),
    emailVerified: true,
    phoneVerified: true,
    toJSON: vi.fn(() => ({ id: 'user-1' })),
    update: vi.fn(),
    destroy: vi.fn(),
    save: vi.fn(),
    ...overrides,
  };
}
