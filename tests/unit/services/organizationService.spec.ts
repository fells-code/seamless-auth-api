/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { UniqueConstraintError } from 'sequelize';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { OrganizationMembership } from '../../../src/models/organizationMemberships.js';
import { Organization } from '../../../src/models/organizations.js';
import { User } from '../../../src/models/users.js';
import {
  createOrganizationForUser,
  normalizeMembershipValues,
  normalizeOrganizationSlug,
} from '../../../src/services/organizationService.js';

describe('normalizeMembershipValues', () => {
  it('trims and drops empty entries', () => {
    expect(normalizeMembershipValues([' members:read ', '', '  '])).toEqual(['members:read']);
  });

  it('returns an empty list for anything that is not an array', () => {
    expect(normalizeMembershipValues(null)).toEqual([]);
    expect(normalizeMembershipValues(undefined)).toEqual([]);
  });

  // The cap is on distinct values. Slicing before deduplicating let repeats consume the
  // whole allowance, so a distinct value behind them was silently discarded.
  it('deduplicates before applying the cap', () => {
    const scopes = [...Array(50).fill('organization:read'), 'members:read'];

    expect(normalizeMembershipValues(scopes)).toEqual(['organization:read', 'members:read']);
  });

  it('still caps the number of distinct values', () => {
    const scopes = Array.from({ length: 80 }, (_, index) => `scope:${index}`);

    expect(normalizeMembershipValues(scopes)).toHaveLength(50);
  });
});

describe('normalizeOrganizationSlug', () => {
  it('slugifies the name when no slug is given', () => {
    expect(normalizeOrganizationSlug('Acme, Inc.')).toBe('acme-inc');
  });

  it('prefers an explicit slug', () => {
    expect(normalizeOrganizationSlug('Acme, Inc.', 'acme-labs')).toBe('acme-labs');
  });

  it('falls back when a name slugifies to nothing', () => {
    expect(normalizeOrganizationSlug('!!!')).toMatch(/^organization-\d+$/);
  });
});

// buildUniqueSlug reads and the insert claims, which are two statements, so the collision
// it exists to avoid still reaches the unique index. The index is the only thing that
// serialises this, so the retry has to be driven by the violation.
describe('createOrganizationForUser', () => {
  const owner = { id: 'user-1', roles: ['user'] } as unknown as User;

  function slugViolation() {
    return new UniqueConstraintError({ fields: { slug: 'acme' } });
  }

  beforeEach(() => {
    vi.clearAllMocks();
    (OrganizationMembership.create as any).mockResolvedValue({ id: 'membership-1' });
  });

  it('takes the next suffix when another create claimed the slug first', async () => {
    (Organization.findOne as any)
      .mockResolvedValueOnce(null)
      .mockResolvedValueOnce({ id: 'organization-1', slug: 'acme' })
      .mockResolvedValueOnce(null);
    (Organization.create as any)
      .mockRejectedValueOnce(slugViolation())
      .mockResolvedValueOnce({ id: 'organization-2', slug: 'acme-2' });

    const { organization } = await createOrganizationForUser({ name: 'Acme', user: owner });

    expect(organization).toEqual({ id: 'organization-2', slug: 'acme-2' });
    expect((Organization.create as any).mock.calls[0][0]).toMatchObject({ slug: 'acme' });
    expect((Organization.create as any).mock.calls[1][0]).toMatchObject({ slug: 'acme-2' });
  });

  it('gives up rather than spinning when the violation never resolves', async () => {
    (Organization.findOne as any).mockResolvedValue(null);
    (Organization.create as any).mockRejectedValue(slugViolation());

    await expect(createOrganizationForUser({ name: 'Acme', user: owner })).rejects.toThrow(
      UniqueConstraintError,
    );
    expect((Organization.create as any).mock.calls).toHaveLength(6);
  });

  it('does not retry a failure that is not a constraint violation', async () => {
    (Organization.findOne as any).mockResolvedValue(null);
    (Organization.create as any).mockRejectedValue(new Error('connection reset'));

    await expect(createOrganizationForUser({ name: 'Acme', user: owner })).rejects.toThrow(
      'connection reset',
    );
    expect((Organization.create as any).mock.calls).toHaveLength(1);
  });
});
