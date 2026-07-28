/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { z } from 'zod';

const AuthEventSummaryItemSchema = z.object({
  type: z.string(),
  count: z.number(),
});

export const AuthEventSummaryResponseSchema = z.object({
  summary: z.array(AuthEventSummaryItemSchema),
});

// `success` and `failed` stay login-only for backwards compatibility. `total` and
// `categories` cover the rest of the auth surface (OTP, WebAuthn, magic link, OAuth, ...).
export const AuthEventTimeseriesResponseSchema = z.object({
  timeseries: z.array(
    z.object({
      bucket: z.string(),
      success: z.number(),
      failed: z.number(),
      total: z.number(),
      categories: z.record(z.string(), z.number()),
    }),
  ),
});

export const GroupedAuthEventSummaryResponseSchema = z.object({
  summary: z.array(AuthEventSummaryItemSchema),
  outcomes: z.array(AuthEventSummaryItemSchema),
});

export const LoginStatsResponseSchema = z.object({
  success: z.number(),
  failed: z.number(),
  successRate: z.number(),
});

const InternalAuthEventSchema = z.object({
  id: z.string().optional(),
  user_id: z.string().nullable().optional(),
  type: z.string(),
  ip_address: z.string().nullable().optional(),
  user_agent: z.string().nullable().optional(),
  metadata: z.record(z.string(), z.unknown()).nullable().optional(),
  created_at: z.coerce
    .date()
    .transform((date) => date.toISOString())
    .optional(),
  updated_at: z.coerce
    .date()
    .transform((date) => date.toISOString())
    .optional(),
});

export const SecurityAnomaliesResponseSchema = z.object({
  suspiciousEvents: z.array(InternalAuthEventSchema),
  total: z.number().int().nonnegative(),
});

export const DashboardMetricsResponseSchema = z.object({
  totalUsers: z.number(),
  activeSessions: z.number(),
  newUsers24h: z.number(),
  loginSuccess24h: z.number(),
  loginFailed24h: z.number(),
  successRate24h: z.number(),
  otpUsage24h: z.number(),
  passkeyUsage24h: z.number(),
  databaseSize: z.number(),
});
