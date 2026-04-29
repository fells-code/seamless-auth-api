/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { SystemConfig as SysConfigModel } from '../models/systemConfig.js';
import { SystemConfig, SystemConfigSchema } from '../schemas/systemConfig.schema.js';
import getLogger from '../utils/logger.js';

const logger = getLogger('getSystemConfig');

let cachedConfig: SystemConfig | null = null;
let lastLoadedAt = 0;

export const CACHE_TTL_MS = 5 * 60 * 1000;

export async function getSystemConfig(): Promise<SystemConfig> {
  const now = Date.now();

  if (cachedConfig && now - lastLoadedAt < CACHE_TTL_MS) {
    return cachedConfig;
  }

  const rows = await SysConfigModel.findAll();
  const configObject = Object.fromEntries(rows.map((row) => [row.key, row.value]));

  const parsed = SystemConfigSchema.safeParse(configObject);
  if (!parsed.success) {
    logger.error('System config failed schema validation on runtime read', {
      issues: parsed.error.issues,
    });
    throw new Error('System configuration is invalid');
  }

  cachedConfig = parsed.data;
  lastLoadedAt = now;

  return cachedConfig;
}

export function invalidateSystemConfigCache() {
  cachedConfig = null;
  lastLoadedAt = 0;
}
