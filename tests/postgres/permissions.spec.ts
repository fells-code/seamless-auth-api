import { randomUUID } from 'crypto';
import { decodeJwt } from 'jose';
import { createRequire } from 'module';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import { invalidateSystemConfigCache } from '../../src/config/getSystemConfig.js';
import { getSequelize, initializeModels } from '../../src/models/index.js';
import { OrganizationRole } from '../../src/models/organizationRoles.js';
import { mintAccessToken } from '../../src/services/accessTokenService.js';
import {
  createPermission,
  deletePermission,
  deleteRoleMappings,
  listRoles,
  permissionsForRoles,
  setRolePermissions,
} from '../../src/services/permissionService.js';
import { buildSystemConfig } from '../factories/systemConfigFactory.js';

vi.hoisted(() => {
  process.env.ISSUER = 'http://localhost:5312';
});

const migration = createRequire(import.meta.url)(
  '../../src/migrations/20261105130000-add-organization-roles.cjs',
);

async function setAvailableRoles(roles: string[]) {
  for (const [key, value] of Object.entries(buildSystemConfig({ available_roles: roles }))) {
    await getSequelize().query(
      `INSERT INTO system_config (key, value, "createdAt", "updatedAt")
       VALUES (:key, CAST(:value AS jsonb), now(), now())
       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
      { replacements: { key, value: JSON.stringify(value) } },
    );
  }
  invalidateSystemConfigCache();
}

function unique(prefix: string) {
  return `${prefix}-${randomUUID().slice(0, 8)}`;
}

const finance = 'finance';

beforeAll(async () => {
  await initializeModels();
});

beforeEach(async () => {
  await getSequelize().query('DELETE FROM role_permissions; DELETE FROM permissions;');
  await setAvailableRoles(['user', finance]);
});

afterAll(async () => {
  await getSequelize().close();
});

describe('the organization role migration', () => {
  it('seeds the built-ins and every held value, spelled as it is, and rewrites nothing', async () => {
    const { Organization, OrganizationMembership, User } = await initializeModels();
    const userId = randomUUID();
    const legacy = `Team Lead ${randomUUID().slice(0, 8)}`;
    const tooLong = 'x'.repeat(90);

    await User.create({ id: userId, email: `${userId}@example.com`, phone: null });
    const organization = await Organization.create({ name: unique('Acme'), slug: unique('acme') });
    const membership = await OrganizationMembership.create({
      organizationId: organization.id,
      userId,
      roles: [legacy, tooLong],
    });

    await migration.up(getSequelize().getQueryInterface());

    const roles = await OrganizationRole.findAll();
    const names = roles.map((role) => role.name);

    expect(roles.filter((role) => role.builtIn).map((role) => role.name)).toEqual(
      expect.arrayContaining(['owner', 'admin', 'member']),
    );
    expect(names).toContain(legacy);
    expect(names).not.toContain(tooLong);
    expect(roles.find((role) => role.name === legacy)?.builtIn).toBe(false);

    await membership.reload();
    expect(membership.roles).toEqual([legacy, tooLong]);
  });
});

describe('a token minted on the deployed schema', () => {
  it('carries the active organization, then loses it when the member is removed', async () => {
    const { Organization, OrganizationMembership, Session, User } = await initializeModels();
    const read = unique('reports:read');
    const write = unique('projects:write');
    await createPermission(read);
    await createPermission(write);
    await setRolePermissions({
      kind: 'instance',
      name: finance,
      permissions: [read],
      actorUserId: null,
    });
    await setRolePermissions({
      kind: 'organization',
      name: 'admin',
      permissions: [write],
      actorUserId: null,
    });

    const userId = randomUUID();
    const user = await User.create({
      id: userId,
      email: `${userId}@example.com`,
      phone: null,
      roles: [finance],
    });
    const organization = await Organization.create({ name: unique('Acme'), slug: unique('acme') });
    const membership = await OrganizationMembership.create({
      organizationId: organization.id,
      userId,
      roles: ['admin'],
    });
    const now = Date.now();
    const session = await Session.create({
      userId,
      organizationId: organization.id,
      mode: 'server',
      refreshTokenLookup: randomUUID(),
      expiresAt: new Date(now + 3_600_000),
      idleExpiresAt: new Date(now + 3_600_000),
    });

    const before = decodeJwt((await mintAccessToken({ session, user })).token);

    expect(before).toMatchObject({
      roles: [finance],
      permissions: [read],
      org_id: organization.id,
      org_roles: ['admin'],
      org_permissions: [write],
    });

    await membership.destroy();

    const after = await mintAccessToken({ session, user });
    const claims = decodeJwt(after.token);

    expect(after.organizationId).toBeNull();
    expect(claims.permissions).toEqual([read]);
    expect(claims).not.toHaveProperty('org_id');
    expect(claims).not.toHaveProperty('org_roles');
    expect(claims).not.toHaveProperty('org_permissions');

    await session.reload();
    expect(session.organizationId).toBeNull();
  });
});

describe('permissions on the deployed schema', () => {
  it('replaces a mapping and reads it back the way a token does', async () => {
    const read = unique('invoices:read');
    const write = unique('invoices:write');
    await createPermission(read);
    await createPermission(write);

    await setRolePermissions({
      kind: 'instance',
      name: finance,
      permissions: [read, write],
      actorUserId: null,
    });
    const change = await setRolePermissions({
      kind: 'instance',
      name: finance,
      permissions: [read],
      actorUserId: null,
    });

    expect(change.removed).toEqual([write]);
    expect(change.added).toEqual([]);
    await expect(permissionsForRoles('instance', [finance])).resolves.toEqual([read]);
    expect((await listRoles()).find((role) => role.name === finance)?.permissions).toEqual([read]);
  });

  it('keeps the kinds of role apart', async () => {
    const read = unique('invoices:read');
    await createPermission(read);
    await setRolePermissions({
      kind: 'instance',
      name: finance,
      permissions: [read],
      actorUserId: null,
    });

    await expect(permissionsForRoles('organization', [finance])).resolves.toEqual([]);
  });

  it('refuses to delete a permission a role grants, at the service and at the key', async () => {
    const read = unique('invoices:read');
    await createPermission(read);
    await setRolePermissions({
      kind: 'instance',
      name: finance,
      permissions: [read],
      actorUserId: null,
    });

    await expect(deletePermission(read)).rejects.toMatchObject({ status: 409 });
    await expect(
      getSequelize().query('DELETE FROM permissions WHERE name = :name', {
        replacements: { name: read },
      }),
    ).rejects.toThrow(/role_permissions_permission_fkey/);
  });

  it('refuses a role kind the schema does not know', async () => {
    const read = unique('invoices:read');
    await createPermission(read);

    await expect(
      getSequelize().query(
        `INSERT INTO role_permissions ("roleKind", "roleName", "permissionName", "createdAt")
         VALUES ('global', 'x', :name, now())`,
        { replacements: { name: read } },
      ),
    ).rejects.toThrow(/role_permissions_role_kind/);
  });

  it('forgets a retired role, so adding the name back grants nothing', async () => {
    const read = unique('invoices:read');
    await createPermission(read);
    await setRolePermissions({
      kind: 'instance',
      name: finance,
      permissions: [read],
      actorUserId: null,
    });

    await expect(deleteRoleMappings('instance', [finance])).resolves.toEqual([finance]);
    await expect(permissionsForRoles('instance', [finance])).resolves.toEqual([]);
  });
});
