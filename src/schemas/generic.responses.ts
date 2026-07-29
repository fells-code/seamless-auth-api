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
]);

export const MessageSchema = z.object({
  message: z.string(),
  token: z.string().optional(),
  delivery: AuthDeliverySchema.optional(),
});

/**
 * The canonical error body. Every 4xx and 5xx response uses this shape, enforced by
 * `tests/unit/routes/errorShapeCoverage.spec.ts`.
 *
 * `error` carries the human-readable reason and is always present. `message` is optional
 * extra detail; it is not a substitute for `error`, so consumers can read one field.
 */
export const ErrorSchema = z.object({
  message: z.string().optional(),
  error: z.string(),
});

/** @deprecated Identical to {@link ErrorSchema}. Kept so route definitions need not churn. */
export const InternalErrorSchema = ErrorSchema;
