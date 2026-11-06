import { randomUUID } from 'crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { invalidateSystemConfigCache } from '../../src/config/getSystemConfig.js';
import { getSequelize, initializeModels } from '../../src/models/index.js';
import {
  createPermission,
  deletePermission,
  deleteRoleMappings,
  listRoles,
  permissionsForRoles,
  setRolePermissions,
} from '../../src/services/permissionService.js';
import { buildSystemConfig } from '../factories/systemConfigFactory.js';

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
