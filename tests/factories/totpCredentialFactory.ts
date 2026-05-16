import { vi } from 'vitest';

export function buildTotpCredential(overrides: any = {}) {
  return {
    id: 'totp-1',
    userId: 'user-1',
    secretCiphertext: 'ciphertext',
    secretIv: 'iv',
    secretTag: 'tag',
    issuer: 'Seamless Auth',
    accountName: 'test@example.com',
    enabled: true,
    verifiedAt: new Date(),
    lastUsedAt: null,
    lastUsedCounter: null,
    createdAt: new Date(),
    updatedAt: new Date(),
    update: vi.fn(),
    destroy: vi.fn(),
    ...overrides,
  };
}
