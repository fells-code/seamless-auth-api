/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import { Response } from 'express';

import { invalidateSystemConfigCache } from '../config/getSystemConfig';
import { SystemConfig } from '../models/systemConfig';
import { User } from '../models/users';
import { PatchSystemConfigSchema } from '../schemas/systemConfig.patch.schema';
import { SystemConfigSchema } from '../schemas/systemConfig.schema';
import { AuthEventService } from '../services/authEventService';
import { ServiceRequest } from '../types/types';
import getLogger from '../utils/logger';

const UpdateSystemConfigSchema = PatchSystemConfigSchema;
const logger = getLogger('systemConfig');

async function getRolesInUse(): Promise<Set<string>> {
  const users = await User.findAll({
    attributes: ['roles'],
  });

  if (!users) {
    return new Set();
  }

  return new Set(users.flatMap((u) => u.roles || []));
}

export async function updateSystemConfig(req: ServiceRequest, res: Response) {
  const actorId = req.triggeredBy;

  logger.debug(`Updating Systeml config. Updated by ${actorId}`);

  if (!actorId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const parsed = UpdateSystemConfigSchema.safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({
      error: 'Invalid system config payload',
      details: parsed.error,
    });
  }

  const rolesInUse = await getRolesInUse();

  if (parsed.data.available_roles) {
    const nextAvailable = new Set(parsed.data.available_roles);

    for (const role of rolesInUse) {
      if (!nextAvailable.has(role)) {
        return res.status(400).json({
          error: 'Role removal blocked',
          message: `Role "${role}" is currently assigned to users and cannot be removed`,
        });
      }
    }
  }

  const updates = parsed.data;

  if (Object.keys(updates).length === 0) {
    return res.status(400).json({
      error: 'No valid configuration values provided',
    });
  }

  const existingRows = await SystemConfig.findAll({
    where: { key: Object.keys(updates) },
  });

  const existingMap = Object.fromEntries(existingRows.map((row) => [row.key, row.value]));

  await SystemConfig.sequelize!.transaction(async (tx) => {
    for (const [key, value] of Object.entries(updates)) {
      await SystemConfig.upsert(
        {
          key,
          value,
          updatedBy: actorId,
        },
        { transaction: tx },
      );
    }
  });

  invalidateSystemConfigCache();

  await AuthEventService.log({
    type: 'system_config_updated',
    userId: actorId,
    req,
    metadata: {
      before: existingMap,
      after: updates,
    },
  });

  return res.status(200).json({
    success: true,
    updatedKeys: Object.keys(updates),
  });
}

export async function getSystemConfigHandler(req: ServiceRequest, res: Response) {
  const actorId = req.triggeredBy;

  if (!actorId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const rows = await SystemConfig.findAll();

  const configObject = Object.fromEntries(rows.map((row) => [row.key, row.value]));

  const parsed = SystemConfigSchema.safeParse(configObject);

  if (!parsed.success) {
    logger.error(`System config has become tainted. Critical issue.`);
    AuthEventService.log({
      userId: actorId,
      type: 'system_config_error',
      req,
      metadata: { reason: 'Failed to parse the system config schema from the database' },
    });
    return res.status(500).json({
      error: 'System configuration is invalid',
    });
  }

  await AuthEventService.log({
    type: 'system_config_read',
    userId: actorId,
    req,
  });

  return res.status(200).json(parsed.data);
}
