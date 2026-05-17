/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { z } from 'zod';

export const LoginMethodSchema = z.enum(['passkey', 'magic_link', 'email_otp', 'phone_otp']);

export const SystemConfigSchema = z.object({
  app_name: z.string().min(3),
  default_roles: z.array(z.string().regex(/^(?!.*[_/\\\s])[A-Za-z0-9-]{1,31}$/)).min(1),
  available_roles: z.array(z.string().regex(/^(?!.*[_/\\\s])[A-Za-z0-9-]{1,31}$/)).min(1),
  login_methods: z.array(LoginMethodSchema).min(1),
  passkey_login_fallback_enabled: z.boolean(),

  access_token_ttl: z.string().regex(/^\d+[smhd]$/),
  refresh_token_ttl: z.string().regex(/^\d+[smhd]$/),

  rate_limit: z.number().int().positive(),
  delay_after: z.number().int().nonnegative(),

  rpid: z.string().min(1),
  origins: z.array(z.url()).min(1),
});

export type SystemConfig = z.infer<typeof SystemConfigSchema>;
