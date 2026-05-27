/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { z } from 'zod';

import { AuthDeliverySchema } from './generic.responses.js';

export const BootstrapAdminInviteBodySchema = z.object({
  email: z.email().max(320),
});

export const BootstrapAdminInviteResponseSchema = z.object({
  success: z.literal(true),
  data: z.object({
    url: z.url().optional(),
    expiresAt: z.iso.datetime(),
    token: z.string().min(32).optional(),
    delivery: AuthDeliverySchema.optional(),
  }),
});

export const BootstrapErrorResponseSchema = z.object({
  success: z.literal(false),
  error: z.object({
    code: z.string(),
    message: z.string(),
  }),
});

export type BootstrapAdminInviteBody = z.infer<typeof BootstrapAdminInviteBodySchema>;
export type BootstrapAdminInviteResponse = z.infer<typeof BootstrapAdminInviteResponseSchema>;
