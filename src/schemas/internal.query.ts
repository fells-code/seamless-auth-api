/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { z } from 'zod';

import { AuthEventTypeEnum } from './authEvent.types.js';

export const PaginationQuerySchema = z.object({
  limit: z.coerce.number().min(1).max(100).optional().default(50),
  offset: z.coerce.number().min(0).optional().default(0),
});

export const AuthEventQuerySchema = z.object({
  limit: z.coerce.number().min(1).max(100).default(10),
  offset: z.coerce.number().min(0).default(0),

  userId: z.string().optional(),
  type: z
    .union([AuthEventTypeEnum, z.string(), z.array(z.union([AuthEventTypeEnum, z.string()]))])
    .optional(),

  from: z.string().optional(),
  to: z.string().optional(),
});

const DAY_MS = 1000 * 60 * 60 * 24;

// A window is capped by the bucket size it would be rendered at, so an hourly
// timeseries cannot be asked for a year of buckets.
export const MAX_METRICS_WINDOW_MS: Record<MetricsInterval, number> = {
  hour: DAY_MS * 31,
  day: DAY_MS * 366,
};

const MetricsIntervalEnum = z.enum(['hour', 'day']);

export type MetricsInterval = z.infer<typeof MetricsIntervalEnum>;

export const MetricsQuerySchema = z
  .object({
    userId: z.string().optional(),
    from: z.string().optional(),
    to: z.string().optional(),
    interval: MetricsIntervalEnum.optional().default('hour'),
  })
  .superRefine((data, ctx) => {
    const fromDate = data.from ? new Date(data.from) : undefined;
    const toDate = data.to ? new Date(data.to) : undefined;

    const fromValid = fromDate !== undefined && !Number.isNaN(fromDate.getTime());
    const toValid = toDate !== undefined && !Number.isNaN(toDate.getTime());

    if (data.from !== undefined && !fromValid) {
      ctx.addIssue({ code: 'custom', path: ['from'], message: 'Invalid from date' });
    }

    if (data.to !== undefined && !toValid) {
      ctx.addIssue({ code: 'custom', path: ['to'], message: 'Invalid to date' });
    }

    if (!fromValid) return;

    // An open-ended window runs to now, so it is measured and capped the same way.
    const end = toValid ? toDate!.getTime() : Date.now();

    if (fromDate!.getTime() > end) {
      ctx.addIssue({ code: 'custom', path: ['to'], message: 'from must be on or before to' });
      return;
    }

    if (end - fromDate!.getTime() > MAX_METRICS_WINDOW_MS[data.interval]) {
      ctx.addIssue({
        code: 'custom',
        path: ['to'],
        message: `time range exceeds the maximum window for the ${data.interval} interval`,
      });
    }
  });
