/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { CredentialApiSchema } from '@seamless-auth/types';
import { z } from 'zod';

import { RoleNameSchema } from './roles.schema.js';

const CredentialWithPrfSchema = CredentialApiSchema.extend({
  prfCapable: z.boolean().optional(),
});

const MeUserSchema = z.object({
  id: z.string(),
  email: z.email(),
  phone: z.string(),
  roles: z.array(RoleNameSchema),
  lastLogin: z.any().optional(),
  activeOrganizationId: z.string().nullable().optional(),
});

const OrganizationMembershipSchema = z.object({
  id: z.string(),
  organizationId: z.string(),
  userId: z.string(),
  roles: z.array(z.string()),
  scopes: z.array(z.string()),
  createdAt: z.any(),
  updatedAt: z.any(),
});

const OrganizationSchema = z.object({
  id: z.string(),
  name: z.string(),
  slug: z.string(),
  createdByUserId: z.string().nullable(),
  metadata: z.record(z.string(), z.unknown()).nullable(),
  createdAt: z.any(),
  updatedAt: z.any(),
  membership: OrganizationMembershipSchema.optional(),
  memberCount: z.number().optional(),
});

export const MeResponseSchema = z.object({
  user: MeUserSchema,
  credentials: z.array(CredentialWithPrfSchema),
  organizations: z.array(OrganizationSchema).optional(),
  activeOrganization: OrganizationSchema.nullable().optional(),
});
