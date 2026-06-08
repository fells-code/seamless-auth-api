/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { z } from 'zod';

export const RegistrationRequestSchema = z.object({
  bootstrapToken: z.string().optional(),
  email: z.email(),
  phone: z.string().nullish(),
});

export const RegisterPhoneRequestSchema = z.object({
  phone: z.string(),
});
