/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { AuthDeliverySchema, ErrorResponseSchema } from '@seamless-auth/types';
import z from 'zod';

export { AuthDeliverySchema } from '@seamless-auth/types';

/**
 * Success envelope for the flows that hand back a token or an external-delivery payload.
 *
 * Deliberately not the shared `MessageResponseSchema`, which is `{ message }` alone and
 * would strip `token` and `delivery` from OTP and magic-link responses.
 */
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
export const ErrorSchema = ErrorResponseSchema;

/** @deprecated Identical to {@link ErrorSchema}. Kept so route definitions need not churn. */
export const InternalErrorSchema = ErrorSchema;
