/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { z } from 'zod';

import { RoleNameSchema } from './roles.schema.js';

export const ApiUserSchema = z
  .object({
    id: z.string(),
    email: z.email(),
    phone: z.string(),
    roles: z.array(RoleNameSchema).default([]),
  })
  .passthrough();
