/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import { z } from 'zod';

import { SystemConfigSchema } from './systemConfig.schema';

export const PatchSystemConfigSchema = SystemConfigSchema.partial().superRefine((data, ctx) => {
  if (
    data.default_roles &&
    data.available_roles &&
    !data.default_roles.every((r) => data.available_roles!.includes(r))
  ) {
    ctx.addIssue({
      path: ['default_roles'],
      message: 'All default roles must exist in available_roles',
      code: z.ZodIssueCode.custom,
    });
  }
});
