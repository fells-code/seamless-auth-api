/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { z } from 'zod';

import { RoleNameSchema } from './roles.schema.js';

export const CreateUserSchema = z.object({
  email: z.email(),
  phone: z.string().nullish(),
  roles: z.array(RoleNameSchema).min(1),
});

export const UpdateUserSchema = z
  .object({
    email: z.email().optional(),
    phone: z.string().min(5).optional(),
    emailVerified: z.boolean().optional(),
    phoneVerified: z.boolean().optional(),
    roles: z.array(RoleNameSchema).min(1).optional(),
  })
  .strict();

export const DeviceReplacementRecoverySchema = z
  .object({
    revokeSessions: z.boolean().default(true),
    removePasskeys: z.boolean().default(true),
    disableTotp: z.boolean().default(true),
  })
  .strict();
