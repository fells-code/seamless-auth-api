/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { z } from 'zod';

import { CredentialResponseSchema } from './credential.responses.js';
import { OrganizationResponseSchema } from './organization.responses.js';
import { RoleNameSchema } from './roles.schema.js';

const MeUserSchema = z.object({
  id: z.string(),
  email: z.email(),
  phone: z.string(),
  roles: z.array(RoleNameSchema),
  lastLogin: z.any().optional(),
  activeOrganizationId: z.string().nullable().optional(),
});

export const MeResponseSchema = z.object({
  user: MeUserSchema,
  credentials: z.array(CredentialResponseSchema),
  organizations: z.array(OrganizationResponseSchema).optional(),
  activeOrganization: OrganizationResponseSchema.nullable().optional(),
});
