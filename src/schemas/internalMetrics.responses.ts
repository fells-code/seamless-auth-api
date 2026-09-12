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

const IntervalStatsSchema = z.object({
  /** How many intervals the percentiles were computed over. */
  count: z.number().int().nonnegative(),
  /** Null when `count` is zero. */
  medianSeconds: z.number().nullable(),
  p90Seconds: z.number().nullable(),
});

/**
 * Each block carries the count it was computed over, so a median of three readings is
 * not mistaken for one of three thousand.
 */
export const FunnelMetricsResponseSchema = z.object({
  /** Self-serve account creation to first completed sign-in, per user. */
  timeToRegistration: IntervalStatsSchema,
  /** `login_success` to the completed sign-in it led to, per attempt. OAuth excluded. */
  timeToLogin: IntervalStatsSchema,
  /** Of the accounts created in the window, how many hold at least one passkey. */
  passkeyAdoption: z.object({
    users: z.number().int().nonnegative(),
    withPasskey: z.number().int().nonnegative(),
    /** `withPasskey / users`, zero when there are no users. */
    rate: z.number().min(0).max(1),
  }),
  /** Account creation to first passkey, for the accounts that enrolled one. */
  timeToFirstPasskey: IntervalStatsSchema,
});
