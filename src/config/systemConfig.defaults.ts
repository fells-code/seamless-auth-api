/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

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
  authenticator_policy: {
    attachment: 'any',
    userVerification: 'required',
    attestation: 'none',
    requireKnownAuthenticator: false,
    syncedPasskeys: 'block',
    aaguidAllowList: [],
    aaguidDenyList: [],
  },
  session_idle_ttl: '8h',
  passkey_login_fallback_enabled: true,
};
