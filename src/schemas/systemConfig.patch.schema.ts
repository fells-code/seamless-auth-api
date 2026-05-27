/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

// src/schemas/systemConfig.patch.schema.ts
import { z } from 'zod';

import type { SystemConfig } from './systemConfig.schema.js';
import {
  LockoutPolicySchema,
  OAuthProviderConfigSchema,
  SystemConfigSchema,
} from './systemConfig.schema.js';

const SystemConfigPatchSchema = z
  .object({
    app_name: SystemConfigSchema.shape.app_name.optional(),
    default_roles: SystemConfigSchema.shape.default_roles.optional(),
    available_roles: SystemConfigSchema.shape.available_roles.optional(),
    login_methods: SystemConfigSchema.shape.login_methods.optional(),
    passkey_login_fallback_enabled:
      SystemConfigSchema.shape.passkey_login_fallback_enabled.optional(),
    oauth_providers: z.array(OAuthProviderConfigSchema).optional(),
    lockout_policy: LockoutPolicySchema.optional(),
    access_token_ttl: SystemConfigSchema.shape.access_token_ttl.optional(),
    refresh_token_ttl: SystemConfigSchema.shape.refresh_token_ttl.optional(),
    rate_limit: SystemConfigSchema.shape.rate_limit.optional(),
    delay_after: SystemConfigSchema.shape.delay_after.optional(),
    rpid: SystemConfigSchema.shape.rpid.optional(),
    origins: SystemConfigSchema.shape.origins.optional(),
  })
  .strict();

export function createPatchSystemConfigSchema(existing: SystemConfig) {
  return SystemConfigPatchSchema.superRefine((data, ctx) => {
    const nextAvailable = data.available_roles ?? existing.available_roles;
    const nextDefault = data.default_roles ?? existing.default_roles;

    if (
      data.available_roles &&
      existing.default_roles.some((r) => !data.available_roles!.includes(r))
    ) {
      ctx.addIssue({
        path: ['available_roles'],
        message: 'Cannot remove roles currently set as default',
        code: z.ZodIssueCode.custom,
      });
    }

    if (nextDefault && nextAvailable && !nextDefault.every((r) => nextAvailable.includes(r))) {
      ctx.addIssue({
        path: ['default_roles'],
        message: 'All default roles must exist in available_roles',
        code: z.ZodIssueCode.custom,
      });
    }
  });
}
