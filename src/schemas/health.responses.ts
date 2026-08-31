/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { z } from 'zod';

export const HealthStatusResponseSchema = z.object({
  message: z.string(),
  /**
   * Present only when something is wrong, so the healthy body is unchanged for
   * anything already parsing it.
   */
  degraded: z
    .object({
      audit: z.object({
        failureCount: z.number(),
        lastFailureAt: z.string().nullable(),
      }),
    })
    .optional(),
});

export const VersionResponseSchema = z.object({
  message: z.string().nullable().optional(),
});
