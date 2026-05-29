/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import z from 'zod';

export const AuthDeliverySchema = z.discriminatedUnion('kind', [
  z.object({
    kind: z.literal('otp_sms'),
    to: z.string(),
    token: z.union([z.string(), z.number()]),
  }),
  z.object({
    kind: z.literal('otp_email'),
    to: z.string(),
    token: z.string(),
  }),
  z.object({
    kind: z.literal('magic_link_email'),
    to: z.string(),
    token: z.string(),
    magicLinkUrl: z.string(),
  }),
  z.object({
    kind: z.literal('bootstrap_invite_email'),
    to: z.string(),
    token: z.string(),
    inviteUrl: z.string(),
  }),
]);

export const MessageSchema = z.object({
  message: z.string(),
  token: z.string().optional(),
  delivery: AuthDeliverySchema.optional(),
});

export const ErrorSchema = z.object({
  message: z.string().optional(),
  error: z.string(),
});

export const InternalErrorSchema = z.object({
  message: z.string().optional(),
  error: z.string(),
});
