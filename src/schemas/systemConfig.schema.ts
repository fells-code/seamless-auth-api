/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import { z } from 'zod';

export const SystemConfigSchema = z.object({
  app_name: z.string().min(3),
  default_roles: z.array(z.string().regex(/^(?!.*[_/\\\s])[A-Za-z0-9-]{1,31}$/)).min(1),
  available_roles: z.array(z.string().regex(/^(?!.*[_/\\\s])[A-Za-z0-9-]{1,31}$/)).min(1),

  access_token_ttl: z.string().regex(/^\d+[smhd]$/),
  refresh_token_ttl: z.string().regex(/^\d+[smhd]$/),

  rate_limit: z.number().int().positive(),
  delay_after: z.number().int().nonnegative(),

  rpid: z.string().min(1),
  origins: z.array(z.url()).min(1),
});

export type SystemConfig = z.infer<typeof SystemConfigSchema>;
