/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { SystemConfig as SysConfigModel } from '../models/systemConfig.js';
import { SystemConfig, SystemConfigSchema } from '../schemas/systemConfig.schema.js';
import getLogger from '../utils/logger.js';

const logger = getLogger('systemConfig');

let cachedConfig: SystemConfig | null = null;
let lastLoadedAt = 0;

const CACHE_TTL_MS = 300_000; // 5 minutes

export async function getSystemConfig(): Promise<SystemConfig> {
  const now = Date.now();

  if (cachedConfig && now - lastLoadedAt < CACHE_TTL_MS) {
    return cachedConfig;
  }

  const rows = await SysConfigModel.findAll();

  const raw = Object.fromEntries(rows.map((row) => [row.key, row.value]));

  const parsed = SystemConfigSchema.safeParse(raw);

  if (!parsed.success) {
    logger.error(`Invalid system_config on runtime load: ${parsed.error.message}`);
    throw new Error('Invalid system_config: runtime configuration failed schema validation');
  }

  cachedConfig = parsed.data;
  lastLoadedAt = now;

  return cachedConfig;
}

export function invalidateSystemConfigCache() {
  cachedConfig = null;
  lastLoadedAt = 0;
}
