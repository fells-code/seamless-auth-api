/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { SystemConfig as SysConfigModel } from '../models/systemConfig.js';
import { SystemConfig, SystemConfigSchema } from '../schemas/systemConfig.schema.js';
import getLogger from '../utils/logger.js';

const logger = getLogger('getSystemConfig');

// Cached, schema-validated copy of the system config row set. Only
// assigned after `SystemConfigSchema.safeParse(...)` succeeds, so every
// cache hit is guaranteed valid. See issue #13.
let cachedConfig: SystemConfig | null = null;
let lastLoadedAt = 0;

// Five minutes — keep the comment in sync with the value. The previous
// "// 30 seconds" comment did not match the actual 300_000 ms (#13).
export const CACHE_TTL_MS = 5 * 60 * 1000;

/**
 * Load the system config from the DB and validate it against
 * `SystemConfigSchema`. The runtime read path now refuses to hand out
 * an unvalidated cast — if a row has become tainted (manual DB edit,
 * out-of-band migration, schema drift) the call throws with a clear
 * error rather than silently returning shape-mismatched data to
 * downstream auth code.
 *
 * Closes https://github.com/fells-code/seamless-auth-api/issues/13.
 */
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
