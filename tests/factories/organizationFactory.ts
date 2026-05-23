import { vi } from 'vitest';

export const testOrganizationId = '2c0d53c2-a541-452b-b71b-54c7f15e5877';

export function buildOrganization(overrides: Partial<any> = {}) {
  return {
    id: testOrganizationId,
    name: 'Acme, Inc.',
    slug: 'acme',
    createdByUserId: 'user-1',
    metadata: null,
    createdAt: new Date('2026-05-18T12:00:00.000Z'),
    updatedAt: new Date('2026-05-18T12:00:00.000Z'),
    update: vi.fn().mockImplementation(function update(this: any, values: any) {
      Object.assign(this, values);
      return Promise.resolve(this);
    }),
    destroy: vi.fn(),
    ...overrides,
  };
}

export function buildOrganizationMembership(overrides: Partial<any> = {}) {
  return {
    id: '47f96fd8-0140-4d18-ad10-f3346dd1df5e',
    organizationId: testOrganizationId,
    userId: 'user-1',
    roles: ['owner', 'admin'],
    scopes: ['organization:read', 'organization:write'],
    createdAt: new Date('2026-05-18T12:00:00.000Z'),
    updatedAt: new Date('2026-05-18T12:00:00.000Z'),
    update: vi.fn().mockImplementation(function update(this: any, values: any) {
      Object.assign(this, values);
      return Promise.resolve(this);
    }),
    destroy: vi.fn(),
    ...overrides,
  };
}
