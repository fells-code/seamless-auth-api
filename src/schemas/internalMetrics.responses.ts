/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { AuthEventSummaryItemSchema, AuthEventTimeseriesPointSchema } from '@seamless-auth/types';
import { z } from 'zod';

import { DEVICE_CLASSES } from '../lib/deviceClass.js';
import { MAIL_PROVIDERS } from '../lib/mailProvider.js';
import { SIGN_IN_METHODS } from '../services/signInMetrics.js';

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

const Count = z.number().int().nonnegative();

/**
 * One row per method, device class, mail provider and owner flag. Consumers pivot on
 * whichever dimension they are reporting; nothing here is pre-aggregated per dimension.
 */
export const SignInBreakdownRowSchema = z.object({
  method: z.enum(SIGN_IN_METHODS),
  /** Null on rows written before the column existed. */
  deviceClass: z.enum(DEVICE_CLASSES).nullable(),
  /** Null when the subject's address was not known when the row was written. */
  mailProvider: z.enum(MAIL_PROVIDERS).nullable(),
  /** Null when the subject was unknown, as distinct from a known non-owner. */
  owner: z.boolean().nullable(),
  /** Attempts in which this method succeeded at least once. */
  success: Count,
  /** Attempts in which this method was presented and never succeeded. */
  failed: Count,
});

export const SignInMetricsResponseSchema = z.object({
  /** `APP_ID`, so rows collected across a fleet stay attributable. Null when unset. */
  deploymentId: z.string().nullable(),
  /**
   * Distinct attempts, counted by attempt id. `delivered` is not a strict step: a
   * passkey attempt reaches `presented` with nothing sent.
   */
  attempts: z.object({
    /** A `login_success` or `user_created` row. */
    started: Count,
    /** A code or link went out. */
    delivered: Count,
    /** A factor was presented, whatever the outcome. */
    presented: Count,
    /** A completed sign-in. */
    completed: Count,
  }),
  signIns: z.object({
    success: Count,
    failed: Count,
    /** `success / (success + failed)`, zero when there is nothing to measure. */
    successRate: z.number().min(0).max(1),
  }),
  breakdown: z.array(SignInBreakdownRowSchema),
});
