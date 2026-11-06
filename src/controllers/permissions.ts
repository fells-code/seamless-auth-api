/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import type { RoleKind } from '@seamless-auth/types';
import { Request, Response } from 'express';
import { ForeignKeyConstraintError } from 'sequelize';

import { resolveAuthorization } from '../services/accessTokenService.js';
import { AuthEventService } from '../services/authEventService.js';
import {
  createPermission as createPermissionRecord,
  deletePermission as deletePermissionRecord,
  listPermissions as listPermissionRecords,
  listRoles as listRoleRecords,
  PermissionError,
  serializePermission,
  setRolePermissions as setRolePermissionRecords,
  updatePermission as updatePermissionRecord,
} from '../services/permissionService.js';
import { AuthenticatedRequest, RouteRequest } from '../types/types.js';

function actorUserId(req: Request) {
  return (req as AuthenticatedRequest).user?.id ?? null;
}

function sendError(res: Response, error: unknown) {
  if (error instanceof PermissionError) {
    return res
      .status(error.status)
      .json({ error: error.message, ...(error.details ? { details: error.details } : {}) });
  }

  throw error;
}

export async function listPermissions(_req: Request, res: Response) {
  const permissions = await listPermissionRecords();

  return res.json({ permissions: permissions.map(serializePermission), total: permissions.length });
}

export async function createPermission(req: Request, res: Response) {
  try {
    const permission = await createPermissionRecord(req.body.name, req.body.description);

    await AuthEventService.log({
      actorUserId: actorUserId(req),
      type: 'admin_permission_created',
      req,
      metadata: { permission: permission.name },
    });

    return res.status(201).json({ permission: serializePermission(permission) });
  } catch (error) {
    return sendError(res, error);
  }
}

export async function updatePermission(req: RouteRequest, res: Response) {
  try {
    const permission = await updatePermissionRecord(
      req.params.permissionName,
      req.body.description,
    );

    await AuthEventService.log({
      actorUserId: actorUserId(req),
      type: 'admin_permission_updated',
      req,
      metadata: { permission: permission.name },
    });

    return res.json({ permission: serializePermission(permission) });
  } catch (error) {
    return sendError(res, error);
  }
}

export async function deletePermission(req: RouteRequest, res: Response) {
  const { permissionName } = req.params;

  try {
    await deletePermissionRecord(permissionName);

    await AuthEventService.log({
      actorUserId: actorUserId(req),
      type: 'admin_permission_deleted',
      req,
      metadata: { permission: permissionName },
    });

    return res.json({ message: 'Success' });
  } catch (error) {
    if (error instanceof ForeignKeyConstraintError) {
      return res.status(409).json({ error: 'Permission is still granted by a role' });
    }

    return sendError(res, error);
  }
}

export async function listRoles(_req: Request, res: Response) {
  return res.json({ roles: await listRoleRecords() });
}

export async function setRolePermissions(req: RouteRequest, res: Response) {
  const kind = req.params.kind as RoleKind;
  const name = req.params.roleName;

  try {
    const { role, added, removed } = await setRolePermissionRecords({
      kind,
      name,
      permissions: req.body.permissions,
      actorUserId: actorUserId(req),
    });

    await AuthEventService.log({
      actorUserId: actorUserId(req),
      type: 'admin_role_permissions_updated',
      req,
      metadata: { kind, role: name, added, removed },
    });

    return res.json({ role });
  } catch (error) {
    return sendError(res, error);
  }
}

export async function getEffectivePermissions(req: Request, res: Response) {
  const authReq = req as AuthenticatedRequest;
  const { roles, permissions } = await resolveAuthorization({
    roles: authReq.user.roles,
    recovery: authReq.recoverySession === true,
  });

  return res.json({
    roles,
    permissions,
    organizationId: null,
    organizationRoles: [],
    organizationPermissions: [],
  });
}
