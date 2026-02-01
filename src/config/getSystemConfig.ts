/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import { SystemConfig as SysConfigModel } from '../models/systemConfig';
import { SystemConfig } from '../schemas/systemConfig.schema';

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
