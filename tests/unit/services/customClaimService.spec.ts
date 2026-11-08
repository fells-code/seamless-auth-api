import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/models/oidcClients.js', () => ({
  OidcClient: { findByPk: vi.fn() },
}));

import { getSystemConfig } from '../../../src/config/getSystemConfig.js';
import { CustomClaim } from '../../../src/models/customClaims.js';
import { OidcClient } from '../../../src/models/oidcClients.js';
import { OrganizationRole } from '../../../src/models/organizationRoles.js';
import {
  CustomClaimError,
  deleteCustomClaimsFor,
  deleteCustomClaimSource,
  getCustomClaimSource,
  listCustomClaimSources,
  resolveCustomClaims,
  serializeCustomClaimSource,
  setCustomClaimSource,
} from '../../../src/services/customClaimService.js';

const at = new Date('2026-11-07T12:00:00.000Z');

function row(sourceKind: string, sourceName: string, claims: Record<string, unknown>) {
  const record: any = { sourceKind, sourceName, claims, createdAt: at, updatedAt: at };
  record.update = vi.fn(async (values: Record<string, unknown>) => Object.assign(record, values));
  record.destroy = vi.fn();
  return record;
}

function stored(...rows: ReturnType<typeof row>[]) {
  vi.mocked(CustomClaim.findAll).mockResolvedValue(rows as never);
}

beforeEach(() => {
  vi.mocked(getSystemConfig).mockResolvedValue({ available_roles: ['user', 'billing'] } as never);
});

describe('resolveCustomClaims', () => {
  it('reads nothing when there are no roles', async () => {
    expect(
      await resolveCustomClaims({ roles: [], organizationRoles: [], hookClaims: null }),
    ).toEqual({});
    expect(CustomClaim.findAll).not.toHaveBeenCalled();
  });

  it('applies instance roles, then organization roles, then the hook, later winning per name', async () => {
    stored(
      row('instance_role', 'user', { plan: 'free', region: 'us', tier: 1 }),
      row('organization_role', 'admin', { plan: 'team', seats: 5 }),
    );

    const resolved = await resolveCustomClaims({
      roles: ['user'],
      organizationRoles: ['admin'],
      hookClaims: { plan: 'enterprise' },
    });

    expect(resolved).toEqual({ plan: 'enterprise', region: 'us', tier: 1, seats: 5 });
  });

  it('applies instance roles in name order, whatever order they were granted in', async () => {
    stored(
      row('instance_role', 'zeta', { plan: 'z' }),
      row('instance_role', 'alpha', { plan: 'a' }),
    );

    const first = await resolveCustomClaims({
      roles: ['zeta', 'alpha'],
      organizationRoles: [],
      hookClaims: null,
    });
    const second = await resolveCustomClaims({
      roles: ['alpha', 'zeta'],
      organizationRoles: [],
      hookClaims: null,
    });

    expect(first).toEqual({ plan: 'z' });
    expect(second).toEqual({ plan: 'z' });
  });

  it('applies organization roles in name order, whatever order they were granted in', async () => {
    stored(
      row('organization_role', 'owner', { plan: 'owner' }),
      row('organization_role', 'billing', { plan: 'billing' }),
    );

    for (const organizationRoles of [
      ['owner', 'billing'],
      ['billing', 'owner'],
    ]) {
      expect(await resolveCustomClaims({ roles: [], organizationRoles, hookClaims: null })).toEqual(
        { plan: 'owner' },
      );
    }
  });

  it('never lets an organization role set apply as an instance one', async () => {
    stored(row('organization_role', 'admin', { plan: 'team' }));

    expect(
      await resolveCustomClaims({ roles: ['admin'], organizationRoles: [], hookClaims: null }),
    ).toEqual({});
  });

  it('filters reserved names, whatever was stored', async () => {
    stored(row('instance_role', 'user', { sub: 'x', org_id: 'y', email: 'z', plan: 'pro' }));

    expect(
      await resolveCustomClaims({
        roles: ['user'],
        organizationRoles: [],
        hookClaims: { iss: 'h' },
      }),
    ).toEqual({ plan: 'pro' });
  });

  it('merges sources whole, leaving the budget to the mint', async () => {
    stored(row('instance_role', 'user', { a: 'x'.repeat(600) }));

    expect(
      await resolveCustomClaims({
        roles: ['user'],
        organizationRoles: [],
        hookClaims: { b: 'y'.repeat(600) },
      }),
    ).toEqual({ a: 'x'.repeat(600), b: 'y'.repeat(600) });
  });

  it('treats a stored set with no claims as empty', async () => {
    stored(row('instance_role', 'user', null as never));
    expect(
      await resolveCustomClaims({ roles: ['user'], organizationRoles: [], hookClaims: undefined }),
    ).toEqual({});
  });
});

describe('admin', () => {
  it('serializes a source', () => {
    expect(serializeCustomClaimSource(row('oidc_client', 'cli', { a: 1 }))).toEqual({
      sourceKind: 'oidc_client',
      sourceName: 'cli',
      claims: { a: 1 },
      updatedAt: at.toISOString(),
    });
    expect(serializeCustomClaimSource(row('oidc_client', 'cli', null as never)).claims).toEqual({});
  });

  it('lists in a stable order', async () => {
    await listCustomClaimSources();
    expect(CustomClaim.findAll).toHaveBeenCalledWith({
      order: [
        ['sourceKind', 'ASC'],
        ['sourceName', 'ASC'],
      ],
    });
  });

  it('answers 404 for a source with no claims', async () => {
    await expect(getCustomClaimSource('instance_role', 'user')).rejects.toMatchObject({
      status: 404,
    });
  });

  it.each([
    ['an instance role outside available_roles', 'instance_role', 'ghost'],
    ['an organization role outside the catalogue', 'organization_role', 'ghost'],
    ['an OpenID Provider client that does not exist', 'oidc_client', 'ghost'],
  ] as const)('refuses %s', async (_name, kind, name) => {
    vi.mocked(OrganizationRole.findByPk).mockResolvedValue(null);
    vi.mocked(OidcClient.findByPk).mockResolvedValue(null);

    await expect(setCustomClaimSource(kind, name, { plan: 'pro' })).rejects.toBeInstanceOf(
      CustomClaimError,
    );
    expect(CustomClaim.create).not.toHaveBeenCalled();
  });

  it('refuses an instance role when no roles are configured', async () => {
    vi.mocked(getSystemConfig).mockResolvedValue({} as never);
    await expect(setCustomClaimSource('instance_role', 'user', {})).rejects.toMatchObject({
      status: 404,
    });
  });

  it('creates a set for a source that exists', async () => {
    vi.mocked(OidcClient.findByPk).mockResolvedValue({ id: 'cli' } as never);
    vi.mocked(CustomClaim.create).mockImplementation(async (values: any) => values);

    const { source, previous } = await setCustomClaimSource('oidc_client', 'cli', { plan: 'pro' });

    expect(source).toMatchObject({ sourceKind: 'oidc_client', claims: { plan: 'pro' } });
    expect(previous).toEqual([]);
  });

  it('replaces an existing set whole', async () => {
    vi.mocked(OrganizationRole.findByPk).mockResolvedValue({ name: 'admin' } as never);
    const existing = row('organization_role', 'admin', { old: 1, kept: 2 });
    vi.mocked(CustomClaim.findOne).mockResolvedValue(existing as never);

    const { previous } = await setCustomClaimSource('organization_role', 'admin', { kept: 3 });

    expect(previous).toEqual(['old', 'kept']);
    expect(existing.update).toHaveBeenCalledWith({ claims: { kept: 3 } });
  });

  it('reports a replaced set that had no claims as empty', async () => {
    const existing = row('instance_role', 'user', null as never);
    vi.mocked(CustomClaim.findOne).mockResolvedValue(existing as never);

    expect((await setCustomClaimSource('instance_role', 'user', {})).previous).toEqual([]);
  });

  it('deletes a set', async () => {
    const existing = row('instance_role', 'user', {});
    vi.mocked(CustomClaim.findOne).mockResolvedValue(existing as never);

    await deleteCustomClaimSource('instance_role', 'user');

    expect(existing.destroy).toHaveBeenCalled();
  });

  it('deletes the sets of sources leaving the instance, and nothing when none', async () => {
    expect(await deleteCustomClaimsFor('instance_role', [])).toBe(0);
    expect(CustomClaim.destroy).not.toHaveBeenCalled();

    await deleteCustomClaimsFor('organization_role', ['legacy']);
    expect(CustomClaim.destroy).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({ sourceKind: 'organization_role' }),
      }),
    );
  });
});
