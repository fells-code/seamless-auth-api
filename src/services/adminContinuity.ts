/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { Request, Response } from 'express';
import { Op } from 'sequelize';

import { hasScopedRole } from '../lib/scopedRoles.js';
import { User } from '../models/users.js';
import { AuthEventService } from './authEventService.js';

const ADMIN_WRITE = 'admin:write';

// Every role string that can grant admin:write, used to narrow the query before the
// exact check. hasScopedRole stays the authority on what each one grants.
const ADMIN_WRITE_GRANTS = ['admin', 'admin:write', 'admin:*'];

/**
 * Whether removing a user, or changing their roles to `nextRoles`, would leave the
 * deployment with nobody who can administer it. `nextRoles` of null means the user is
 * going away.
 *
 * The only way back from that state is a direct database edit, because `OWNER_EMAIL`
 * grants admin only when the account is created.
 */
export async function wouldLeaveNoAdmin(
  user: { id: string; roles?: string[] | null },
  nextRoles: string[] | null,
): Promise<boolean> {
  if (!hasScopedRole(user.roles ?? [], ADMIN_WRITE)) {
    return false;
  }

  if (nextRoles && hasScopedRole(nextRoles, ADMIN_WRITE)) {
    return false;
  }

  const others = await User.findAll({
    attributes: ['id', 'roles'],
    where: {
      id: { [Op.ne]: user.id },
      revoked: false,
      roles: { [Op.overlap]: ADMIN_WRITE_GRANTS },
    },
  });

  return !others.some((other) => hasScopedRole(other.roles ?? [], ADMIN_WRITE));
}

export async function refuseLastAdminChange(params: {
  req: Request;
  res: Response;
  targetUserId: string;
  actorUserId?: string | null;
  action: 'delete' | 'role_change' | 'self_delete';
}) {
  await AuthEventService.log({
    userId: params.targetUserId,
    actorUserId: params.actorUserId ?? null,
    type: 'admin_last_admin_change_refused',
    req: params.req,
    metadata: { action: params.action },
  });

  return params.res.status(409).json({
    error: 'last_admin',
    message:
      'This would leave no one able to administer this deployment. Give another user admin:write first.',
  });
}
