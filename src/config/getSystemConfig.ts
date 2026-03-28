/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { SystemConfig as SysConfigModel } from '../models/systemConfig.js';
import { SystemConfig } from '../schemas/systemConfig.schema.js';

let cachedConfig: { [k: string]: unknown } | null;
let lastLoadedAt = 0;

const CACHE_TTL_MS = 300_000; // 30 seconds

export async function getSystemConfig(): Promise<SystemConfig> {
  const now = Date.now();

  if (cachedConfig && now - lastLoadedAt < CACHE_TTL_MS) {
    return cachedConfig as SystemConfig;
  }

  const rows = await SysConfigModel.findAll();

  cachedConfig = Object.fromEntries(rows.map((row) => [row.key, row.value]));

  lastLoadedAt = now;

  return cachedConfig as SystemConfig;
}

export function invalidateSystemConfigCache() {
  cachedConfig = null;
  lastLoadedAt = 0;
}
