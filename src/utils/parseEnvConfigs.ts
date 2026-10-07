/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
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
    case 'magic_link_redirect_uris':
    case 'origins':
      return raw
        .split(',')
        .map((v) => v.trim())
        .filter(Boolean);

    case 'oauth_providers':
      return z.array(OAuthProviderConfigSchema).parse(JSON.parse(raw));

    case 'lockout_policy':
    case 'authenticator_policy':
    case 'flow_rate_limits':
      return JSON.parse(raw);

    case 'rate_limit':
    case 'delay_after':
      return Number(raw);

    // One of the words an operator is likely to reach for means no limit. Without
    // this the only way to express "uncapped" through the environment would be to
    // unset the variable, which a deployment template cannot easily do.
    //
    // A truly empty value never gets here: bootstrapSystemConfig skips empty env
    // values, so they count as unset (an existing cap is kept, otherwise the
    // default applies). The empty check below only catches a whitespace-only
    // value, which is empty once trimmed.
    case 'max_concurrent_sessions': {
      const value = raw.trim().toLowerCase();

      if (value === '' || value === 'null' || value === 'none' || value === 'unlimited') {
        return null;
      }

      return Number(raw);
    }

    case 'passkey_login_fallback_enabled':
    case 'prompt_passkey_enrollment':
    case 'phishing_resistant_only':
      return raw.trim().toLowerCase() === 'true';

    case 'access_token_ttl':
    case 'session_idle_ttl':
    case 'refresh_token_ttl':
    case 'rpid':
    case 'app_name':
    case 'frontend_url':
      return raw;

    default:
      throw new Error(`Unhandled system config key: ${key}`);
  }
}
