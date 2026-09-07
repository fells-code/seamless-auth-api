/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { AuthenticatorPolicySchema } from '@seamless-auth/types';

import type { SystemConfig } from '../schemas/systemConfig.schema.js';

export const SYSTEM_CONFIG_DEFAULTS: Partial<SystemConfig> = {
  login_methods: ['passkey', 'magic_link'],
  oauth_providers: [],
  lockout_policy: {
    enabled: true,
    maxFailures: 10,
    windowSeconds: 15 * 60,
    lockoutSeconds: 15 * 60,
  },
  // Parsed from the schema rather than restated, so a field added upstream arrives with
  // the default the schema gives it instead of being absent here until someone notices.
  // syncedPasskeys is named because the schema defaulted it to 'block' up to
  // @seamless-auth/types 0.18.0, which refused every iCloud Keychain and Google Password
  // Manager passkey and so failed the first registration on a stock install. Naming it
  // seeds the right value on either version. Drop it once the floor is 0.19.0.
  authenticator_policy: AuthenticatorPolicySchema.parse({ syncedPasskeys: 'allow' }),
  session_idle_ttl: '8h',
  // No cap unless a deployment asks for one, so nothing changes for an instance
  // that predates the key.
  max_concurrent_sessions: null,
  passkey_login_fallback_enabled: true,
};
