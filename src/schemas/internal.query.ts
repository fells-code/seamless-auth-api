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

const MAX_METRICS_WINDOW_MS = 1000 * 60 * 60 * 24 * 366; // ~1 year

export const MetricsQuerySchema = z
  .object({
    userId: z.string().optional(),
    from: z.string().optional(),
    to: z.string().optional(),
    interval: z.enum(['hour', 'day']).optional().default('hour'),
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

    if (fromValid && toValid) {
      if (fromDate!.getTime() > toDate!.getTime()) {
        ctx.addIssue({ code: 'custom', path: ['to'], message: 'from must be on or before to' });
      } else if (toDate!.getTime() - fromDate!.getTime() > MAX_METRICS_WINDOW_MS) {
        ctx.addIssue({
          code: 'custom',
          path: ['to'],
          message: 'time range exceeds the maximum window',
        });
      }
    }
  });
