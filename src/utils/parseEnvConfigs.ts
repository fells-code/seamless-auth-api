/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import { SYSTEM_CONFIG_ENV_MAP } from '../config/systemConfig.envMap';

export function parseSystemConfigEnvValue(key: keyof typeof SYSTEM_CONFIG_ENV_MAP, raw: string) {
  switch (key) {
    case 'default_roles':
    case 'available_roles':
    case 'origins':
      return raw
        .split(',')
        .map((v) => v.trim())
        .filter(Boolean);

    case 'rate_limit':
    case 'delay_after':
      return Number(raw);

    case 'access_token_ttl':
    case 'refresh_token_ttl':
    case 'rpid':
    case 'app_name':
      return raw;

    default:
      throw new Error(`Unhandled system config key: ${key}`);
  }
}
