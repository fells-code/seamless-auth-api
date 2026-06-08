/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { z } from 'zod';

import { RoleNameSchema } from './roles.schema.js';

const IsoDateSchema = z.coerce.date().transform((date) => date.toISOString());

export const ApiUserSchema = z
  .object({
    id: z.string(),
    email: z.email(),
    phone: z.string().nullable(),
    roles: z.array(RoleNameSchema).default([]),
    revoked: z.boolean().optional(),
    emailVerified: z.boolean().optional(),
    phoneVerified: z.boolean().optional(),
    verified: z.boolean().optional(),
    lastLogin: IsoDateSchema.nullable().optional(),
    createdAt: IsoDateSchema.optional(),
    updatedAt: IsoDateSchema.optional(),
  })
  .strict();
