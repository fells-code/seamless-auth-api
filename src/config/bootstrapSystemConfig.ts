/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import { SystemConfig } from '../models/systemConfig';
import { SystemConfigSchema } from '../schemas/systemConfig.schema';
import { parseSystemConfigEnvValue } from '../utils/parseEnvConfigs';
import { SYSTEM_CONFIG_ENV_MAP } from './systemConfig.envMap';

export async function bootstrapSystemConfig() {
  const resolvedConfig: Record<string, unknown> = {};

  for (const [key, envVar] of Object.entries(SYSTEM_CONFIG_ENV_MAP)) {
    const existing = await SystemConfig.findByPk(key);

    if (existing) {
      resolvedConfig[key] = existing.value;
      continue;
    }

    const envValue = process.env[envVar];
    if (!envValue) {
      throw new Error(
        `Missing required system config "${key}". ` +
          `Provide ENV ${envVar} or seed system_config.`,
      );
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
