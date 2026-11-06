/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import type { RoleDefinition, RoleKind } from '@seamless-auth/types';
import { Op, Transaction, UniqueConstraintError } from 'sequelize';

import { getSystemConfig } from '../config/getSystemConfig.js';
import { Permission } from '../models/permissions.js';
import { RolePermission } from '../models/rolePermissions.js';

export class PermissionError extends Error {
  constructor(
    readonly status: number,
    message: string,
    readonly details?: Record<string, unknown>,
  ) {
    super(message);
    this.name = 'PermissionError';
  }
}

export function serializePermission(permission: Permission) {
  return {
    id: permission.id,
    name: permission.name,
    description: permission.description ?? null,
    createdAt: permission.createdAt,
    updatedAt: permission.updatedAt,
  };
}

export async function listPermissions() {
  return Permission.findAll({ order: [['name', 'ASC']] });
}

export async function createPermission(name: string, description?: string) {
  try {
    return await Permission.create({ name, description: description ?? null });
  } catch (error) {
    if (error instanceof UniqueConstraintError) {
      throw new PermissionError(409, 'Permission already exists');
    }

    throw error;
  }
}

export async function updatePermission(name: string, description: string | null) {
  const permission = await Permission.findOne({ where: { name } });

  if (!permission) {
    throw new PermissionError(404, 'Permission not found');
  }

  await permission.update({ description });

  return permission;
}

/**
 * Refused while a role still grants it. Taking access away is a decision about the role, so
 * it has to be made there, where it can be seen. The foreign key holds the same line against
 * a mapping written between the two statements here.
 */
export async function deletePermission(name: string) {
  const permission = await Permission.findOne({ where: { name } });

  if (!permission) {
    throw new PermissionError(404, 'Permission not found');
  }

  const grantedBy = await RolePermission.findAll({ where: { permissionName: name } });

  if (grantedBy.length > 0) {
    throw new PermissionError(409, 'Permission is still granted by a role', {
      roles: grantedBy.map(({ roleKind, roleName }) => ({ kind: roleKind, name: roleName })),
    });
  }

  await permission.destroy();
}

async function mappingsByRole(roleKind: RoleKind) {
  const mappings = await RolePermission.findAll({
    where: { roleKind },
    order: [['permissionName', 'ASC']],
  });
  const byRole = new Map<string, string[]>();

  for (const { roleName, permissionName } of mappings) {
    byRole.set(roleName, [...(byRole.get(roleName) ?? []), permissionName]);
  }

  return byRole;
}

function instanceRole(name: string, permissions: string[]): RoleDefinition {
  return { name, kind: 'instance', description: null, builtIn: false, permissions };
}

export async function listRoles(): Promise<RoleDefinition[]> {
  const [{ available_roles }, instanceMappings] = await Promise.all([
    getSystemConfig(),
    mappingsByRole('instance'),
  ]);

  return (available_roles ?? []).map((name) =>
    instanceRole(name, instanceMappings.get(name) ?? []),
  );
}

async function findRole(kind: RoleKind, name: string) {
  const roles = await listRoles();

  return roles.find((role) => role.kind === kind && role.name === name) ?? null;
}

/**
 * Replaces the role's mapping as a whole. Returns the role and what changed, for the audit
 * event. The role has to exist and every permission has to be in the catalogue: a grant
 * naming a permission nothing defines would read as access control while controlling nothing.
 */
export async function setRolePermissions({
  kind,
  name,
  permissions,
  actorUserId,
}: {
  kind: RoleKind;
  name: string;
  permissions: string[];
  actorUserId: string | null;
}) {
  const role = await findRole(kind, name);

  if (!role) {
    throw new PermissionError(404, 'Role not found');
  }

  const next = Array.from(new Set(permissions)).sort();
  const known = await Permission.findAll({ where: { name: { [Op.in]: next } } });
  const knownNames = new Set(known.map((permission) => permission.name));
  const unknown = next.filter((permission) => !knownNames.has(permission));

  if (unknown.length > 0) {
    throw new PermissionError(400, 'Unknown permissions', { permissions: unknown });
  }

  const previous = await RolePermission.sequelize!.transaction(async (transaction) => {
    const current = await RolePermission.findAll({
      where: { roleKind: kind, roleName: name },
      transaction,
      lock: transaction.LOCK.UPDATE,
    });

    await RolePermission.destroy({ where: { roleKind: kind, roleName: name }, transaction });
    await RolePermission.bulkCreate(
      next.map((permissionName) => ({
        roleKind: kind,
        roleName: name,
        permissionName,
        createdBy: actorUserId,
      })),
      { transaction },
    );

    return current.map((mapping) => mapping.permissionName);
  });

  return {
    role: { ...role, permissions: next },
    added: next.filter((permission) => !previous.includes(permission)),
    removed: previous.filter((permission) => !next.includes(permission)),
  };
}

/**
 * For a role leaving the instance. Without this, adding the name back later would silently
 * restore whatever it used to grant. Returns the roles that held any mapping, for the audit.
 */
export async function deleteRoleMappings(
  kind: RoleKind,
  names: string[],
  transaction?: Transaction,
) {
  if (names.length === 0) return [];

  const where = { roleKind: kind, roleName: { [Op.in]: names } };
  const mappings = await RolePermission.findAll({ where, transaction });

  if (mappings.length === 0) return [];

  await RolePermission.destroy({ where, transaction });

  return Array.from(new Set(mappings.map((mapping) => mapping.roleName)));
}

/**
 * What the roles grant. Keyed on the literal name held: holding `billing` does not pick up a
 * mapping on `billing:read`, so the console can show exactly why someone has a permission.
 */
export async function permissionsForRoles(
  kind: RoleKind,
  roles: string[] | null | undefined,
  transaction?: Transaction,
) {
  if (!roles?.length) return [];

  const mappings = await RolePermission.findAll({
    where: { roleKind: kind, roleName: { [Op.in]: roles } },
    attributes: ['permissionName'],
    transaction,
  });

  return Array.from(new Set(mappings.map((mapping) => mapping.permissionName))).sort();
}
