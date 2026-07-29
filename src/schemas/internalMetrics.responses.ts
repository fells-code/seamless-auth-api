/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { AuthEventSummaryItemSchema, AuthEventTimeseriesPointSchema } from '@seamless-auth/types';
import { z } from 'zod';

export {
  AuthEventSummaryResponseSchema,
  DashboardMetricsResponseSchema,
  LoginStatsResponseSchema,
  SecurityAnomaliesResponseSchema,
} from '@seamless-auth/types';

/**
 * `success` and `failed` stay login-only for backwards compatibility. `total` and
 * `categories` cover the rest of the auth surface (OTP, WebAuthn, magic link, OAuth).
 *
 * The shared point schema stops at the login-only trio, so the extra fields are added
 * here rather than dropped.
 */
export const AuthEventTimeseriesResponseSchema = z.object({
  timeseries: z.array(
    AuthEventTimeseriesPointSchema.extend({
      total: z.number(),
      categories: z.record(z.string(), z.number()),
    }),
  ),
});

export const GroupedAuthEventSummaryResponseSchema = z.object({
  summary: z.array(AuthEventSummaryItemSchema),
  outcomes: z.array(AuthEventSummaryItemSchema),
});
