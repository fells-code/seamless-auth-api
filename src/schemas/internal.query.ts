/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import {
  type MetricsInterval,
  MetricsQuerySchema as SharedMetricsQuerySchema,
} from '@seamless-auth/types';
import { z } from 'zod';

import { AuthEventTypeEnum } from './authEvent.types.js';

export { PaginationQuerySchema } from '@seamless-auth/types';

/**
 * Kept local because the shared package still declares the 15 auth event types this
 * server removed as never-emitted. Re-exporting it would reintroduce them into the
 * documented filter values and contradict the pruning.
 */
export const AuthEventQuerySchema = z.object({
  limit: z.coerce.number().min(1).max(100).default(10),
  offset: z.coerce.number().min(0).default(0),

  userId: z.string().optional(),
  /** Filters to what one administrator did, rather than what happened to one user. */
  actorUserId: z.string().optional(),
  type: z
    .union([AuthEventTypeEnum, z.string(), z.array(z.union([AuthEventTypeEnum, z.string()]))])
    .optional(),

  from: z.string().optional(),
  to: z.string().optional(),
});

const DAY_MS = 1000 * 60 * 60 * 24;

export type { MetricsInterval };

// A window is capped by the bucket size it would be rendered at, so an hourly
// timeseries cannot be asked for a year of buckets.
export const MAX_METRICS_WINDOW_MS: Record<MetricsInterval, number> = {
  hour: DAY_MS * 31,
  day: DAY_MS * 366,
};

/**
 * The shared schema already rejects unparseable and inverted ranges, and caps the total
 * span. It does not cap by interval, so it would accept a 90 day hourly window, which is
 * 2160 buckets in one response. That rule is layered on here rather than pushed into the
 * shared contract, because the cap follows from how this server renders buckets.
 */
export const MetricsQuerySchema = SharedMetricsQuerySchema.superRefine((data, ctx) => {
  const fromDate = data.from ? new Date(data.from) : undefined;
  if (!fromDate || Number.isNaN(fromDate.getTime())) return;

  const toDate = data.to ? new Date(data.to) : undefined;
  const toValid = toDate !== undefined && !Number.isNaN(toDate.getTime());

  // An open-ended window runs to now, so it is measured and capped the same way. The
  // shared schema only compares `from` against an explicit `to`, so the future-dated
  // open-ended case is caught here.
  const end = toValid ? toDate!.getTime() : Date.now();

  if (fromDate.getTime() > end) {
    ctx.addIssue({ code: 'custom', path: ['to'], message: 'from must be on or before to' });
    return;
  }

  if (end - fromDate.getTime() > MAX_METRICS_WINDOW_MS[data.interval]) {
    ctx.addIssue({
      code: 'custom',
      path: ['to'],
      message: `time range exceeds the maximum window for the ${data.interval} interval`,
    });
  }
});
