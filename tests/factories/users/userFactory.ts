import { vi } from 'vitest';

let idCounter = 1;

export function buildUser(overrides: Partial<any> = {}) {
  return {
    id: `user-${Date.now()}`,
    email: 'test@example.com',
    phone: '+14155552671', // ✅ VALID US number
    roles: ['user'],
    ...overrides,
  };
}

export function mockUserModel() {
  return {
    findOne: vi.fn(),
    create: vi.fn(),
  };
}
