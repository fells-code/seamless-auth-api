/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { describe, expect, it } from 'vitest';

import {
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
