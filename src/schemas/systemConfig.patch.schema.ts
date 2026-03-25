/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
// src/schemas/systemConfig.patch.schema.ts
import { z } from 'zod';

import type { SystemConfig } from './systemConfig.schema.js';
import { SystemConfigSchema } from './systemConfig.schema.js';

export function createPatchSystemConfigSchema(existing: SystemConfig) {
  return SystemConfigSchema.partial().superRefine((data, ctx) => {
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
