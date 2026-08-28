/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { z } from 'zod';

import { SYSTEM_CONFIG_ENV_MAP } from '../config/systemConfig.envMap.js';
import { OAuthProviderConfigSchema } from '../schemas/systemConfig.schema.js';

export function parseSystemConfigEnvValue(key: keyof typeof SYSTEM_CONFIG_ENV_MAP, raw: string) {
  switch (key) {
    case 'default_roles':
    case 'available_roles':
    case 'login_methods':
    case 'origins':
      return raw
        .split(',')
        .map((v) => v.trim())
        .filter(Boolean);

    case 'oauth_providers':
      return z.array(OAuthProviderConfigSchema).parse(JSON.parse(raw));

    case 'lockout_policy':
    case 'authenticator_policy':
      return JSON.parse(raw);

    case 'rate_limit':
    case 'delay_after':
      return Number(raw);

    case 'passkey_login_fallback_enabled':
      return raw.trim().toLowerCase() === 'true';

    case 'access_token_ttl':
    case 'refresh_token_ttl':
    case 'rpid':
    case 'app_name':
    case 'frontend_url':
      return raw;

    default:
      throw new Error(`Unhandled system config key: ${key}`);
  }
}
