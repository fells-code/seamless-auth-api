/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import type { SystemConfig } from '../schemas/systemConfig.schema.js';

export const SYSTEM_CONFIG_DEFAULTS: Partial<SystemConfig> = {
  login_methods: ['passkey', 'magic_link'],
  passkey_login_fallback_enabled: true,
};
