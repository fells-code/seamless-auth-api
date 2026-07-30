/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { Request, Response } from 'express';

import { getSystemConfig, invalidateSystemConfigCache } from '../config/getSystemConfig.js';
import { resolveSystemConfigUpdatedBy } from '../lib/systemConfigActor.js';
import { SystemConfig } from '../models/systemConfig.js';
import { User } from '../models/users.js';
import { createPatchSystemConfigSchema } from '../schemas/systemConfig.patch.schema.js';
import { SystemConfigSchema } from '../schemas/systemConfig.schema.js';
import { AuthEventService } from '../services/authEventService.js';
import { getLoginPolicy } from '../services/loginPolicyService.js';
import { ServiceRequest } from '../types/types.js';
import getLogger from '../utils/logger.js';

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
  logger.info('Updating system config');
  const existing = await getSystemConfig();

  const schema = createPatchSystemConfigSchema(existing);

  const parsed = schema.safeParse(req.body);

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

  const updatedBy = resolveSystemConfigUpdatedBy(req);

  await SystemConfig.sequelize!.transaction(async (tx) => {
    for (const [key, value] of Object.entries(updates)) {
      await SystemConfig.upsert(
        {
          key,
          value,
          // Mark the row as admin-managed so bootstrap won't overwrite it from env.
          updatedBy,
        },
        { transaction: tx },
      );
    }
  });

  invalidateSystemConfigCache();

  await AuthEventService.log({
    type: 'system_config_updated',
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
  const rows = await SystemConfig.findAll();

  const configObject = Object.fromEntries(rows.map((row) => [row.key, row.value]));

  const parsed = SystemConfigSchema.safeParse(configObject);

  if (!parsed.success) {
    logger.error(`System config has become tainted. Critical issue.`);
    AuthEventService.log({
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
    req,
  });

  return res.status(200).json(parsed.data);
}

export const getAvailableRoles = async (_req: Request, res: Response) => {
  const config = await getSystemConfig();

  return res.json({
    roles: config.available_roles ?? [],
  });
};

/**
 * The configuration a signed-out client is allowed to read.
 *
 * Served through getLoginPolicy rather than off the raw config so a tainted or
 * partially written config still answers with the defaults. The sign-in screens
 * call this before anyone has a session, so failing here would leave a client
 * with no methods to offer at all.
 *
 * Only add a key to this response when a signed-out client genuinely cannot work
 * without it. Everything else belongs on the admin routes.
 */
export const getPublicSystemConfig = async (_req: Request, res: Response) => {
  const { loginMethods } = await getLoginPolicy();

  return res.json({ loginMethods });
};
