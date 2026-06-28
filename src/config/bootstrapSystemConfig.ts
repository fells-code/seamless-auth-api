/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { SystemConfig } from '../models/systemConfig.js';
import { SystemConfigSchema } from '../schemas/systemConfig.schema.js';
import { parseSystemConfigEnvValue } from '../utils/parseEnvConfigs.js';
import { SYSTEM_CONFIG_DEFAULTS } from './systemConfig.defaults.js';
import { SYSTEM_CONFIG_ENV_MAP } from './systemConfig.envMap.js';

export async function bootstrapSystemConfig() {
  const resolvedConfig: Record<string, unknown> = {};

  for (const [key, envVar] of Object.entries(SYSTEM_CONFIG_ENV_MAP)) {
    const existing = await SystemConfig.findByPk(key);
    const envValue = process.env[envVar];

    if (existing) {
      // Re-apply the env value over config that hasn't been changed through the
      // admin API (updatedBy IS NULL), so env-mapped config stays authoritative
      // unless an admin has overridden it at runtime. Without this, a migration
      // that seeds a default would permanently shadow the env var.
      if (envValue && existing.updatedBy == null) {
        const parsed = parseSystemConfigEnvValue(
          key as keyof typeof SYSTEM_CONFIG_ENV_MAP,
          envValue,
        );

        if (JSON.stringify(existing.value) !== JSON.stringify(parsed)) {
          await existing.update({ value: parsed });
        }

        resolvedConfig[key] = parsed;
      } else {
        resolvedConfig[key] = existing.value;
      }

      continue;
    }

    if (!envValue) {
      const defaultValue = SYSTEM_CONFIG_DEFAULTS[key as keyof typeof SYSTEM_CONFIG_DEFAULTS];

      if (defaultValue === undefined) {
        throw new Error(
          `Missing required system config "${key}". ` +
            `Provide ENV ${envVar} or seed system_config.`,
        );
      }

      await SystemConfig.create({
        key,
        value: defaultValue,
        updatedBy: null,
      });

      resolvedConfig[key] = defaultValue;
      continue;
    }

    const parsed = parseSystemConfigEnvValue(key as keyof typeof SYSTEM_CONFIG_ENV_MAP, envValue);

    await SystemConfig.create({
      key,
      value: parsed,
      updatedBy: null,
    });

    resolvedConfig[key] = parsed;
  }

  const validated = SystemConfigSchema.safeParse(resolvedConfig);
  if (!validated.success) {
    throw new Error(`Invalid system configuration:\n${validated.error.toString()}`);
  }

  return validated.data;
}
