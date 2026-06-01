/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { z } from 'zod';

const OrganizationMembershipUserSchema = z.object({
  id: z.string(),
  email: z.email(),
  phone: z.string(),
  roles: z.array(z.string()),
});

export const OrganizationMembershipResponseSchema = z.object({
  id: z.string(),
  organizationId: z.string(),
  userId: z.string(),
  roles: z.array(z.string()),
  scopes: z.array(z.string()),
  createdAt: z.any(),
  updatedAt: z.any(),
  user: OrganizationMembershipUserSchema.optional(),
});

export const OrganizationResponseSchema = z.object({
  id: z.string(),
  name: z.string(),
  slug: z.string(),
  createdByUserId: z.string().nullable(),
  metadata: z.record(z.string(), z.unknown()).nullable(),
  createdAt: z.any(),
  updatedAt: z.any(),
  membership: OrganizationMembershipResponseSchema.optional(),
  memberCount: z.number().int().nonnegative().optional(),
});

export const OrganizationEnvelopeResponseSchema = z.object({
  organization: OrganizationResponseSchema,
});

export const OrganizationListResponseSchema = z.object({
  organizations: z.array(OrganizationResponseSchema),
  activeOrganizationId: z.string().nullable(),
});

export const AdminOrganizationListResponseSchema = z.object({
  organizations: z.array(OrganizationResponseSchema),
  total: z.number().int().nonnegative(),
});

export const OrganizationMembersResponseSchema = z.object({
  members: z.array(OrganizationMembershipResponseSchema),
  total: z.number().int().nonnegative(),
});

export const OrganizationMembershipEnvelopeResponseSchema = z.object({
  membership: OrganizationMembershipResponseSchema,
});

export const OrganizationSwitchResponseSchema = z.object({
  message: z.string(),
  token: z.string(),
  sub: z.string(),
  sessionId: z.string(),
  organizationId: z.string(),
  organization: OrganizationResponseSchema,
  ttl: z.number(),
});
