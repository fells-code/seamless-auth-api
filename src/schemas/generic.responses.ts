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

/**
 * The error body for a request that fails schema validation in `defineRoute`.
 *
 * A superset of {@link ErrorSchema}: `error` stays required and carries the stable
 * code, and `details` names which fields were rejected. Kept separate because a
 * plain error schema would strip that list before it reached the caller, which is
 * the same reason `AdminValidationErrorSchema` exists for the user endpoints.
 *
 * `defineRoute` declares this for any route that validates a request, so the
 * documented 400 matches what validation actually answers with.
 */
export const ValidationErrorSchema = z.object({
  error: z.string(),
  message: z.string().optional(),
  details: z
    .object({
      issues: z.array(
        z.object({
          path: z.array(z.union([z.string(), z.number()])),
          code: z.string(),
          message: z.string(),
        }),
      ),
    })
    .optional(),
});
