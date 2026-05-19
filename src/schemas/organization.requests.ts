/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { z } from 'zod';

const MetadataSchema = z.record(z.string(), z.unknown()).nullable().optional();

export const OrganizationIdParamSchema = z.object({
  organizationId: z.string().uuid(),
});

export const OrganizationMemberParamSchema = OrganizationIdParamSchema.extend({
  userId: z.string().uuid(),
});

export const CreateOrganizationRequestSchema = z.object({
  name: z.string().trim().min(1).max(120),
  slug: z.string().trim().min(1).max(100).optional(),
  metadata: MetadataSchema,
});

export const UpdateOrganizationRequestSchema = z.object({
  name: z.string().trim().min(1).max(120).optional(),
  slug: z.string().trim().min(1).max(100).optional(),
  metadata: MetadataSchema,
});

export const AddOrganizationMemberRequestSchema = z
  .object({
    userId: z.string().uuid().optional(),
    email: z.string().email().optional(),
    roles: z.array(z.string().trim().min(1).max(80)).optional(),
    scopes: z.array(z.string().trim().min(1).max(120)).optional(),
  })
  .refine((value) => Boolean(value.userId || value.email), {
    message: 'userId or email is required',
  });

export const UpdateOrganizationMemberRequestSchema = z.object({
  roles: z.array(z.string().trim().min(1).max(80)).optional(),
  scopes: z.array(z.string().trim().min(1).max(120)).optional(),
});
