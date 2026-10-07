/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { z } from 'zod';

export const REVIEW_ACCOUNT_USAGE_DEFAULT_DAYS = 30;
export const REVIEW_ACCOUNT_USAGE_MAX_DAYS = 366;

export const ReviewAccountsQuerySchema = z.object({
  days: z.coerce
    .number()
    .int()
    .min(1)
    .max(REVIEW_ACCOUNT_USAGE_MAX_DAYS)
    .default(REVIEW_ACCOUNT_USAGE_DEFAULT_DAYS),
});

export type ReviewAccountsQuery = z.infer<typeof ReviewAccountsQuerySchema>;

export const ReviewAccountsResponseSchema = z.object({
  enabled: z.boolean(),
  emails: z.array(z.string()),
  codeConfigured: z.boolean(),
  recentSignIns: z.object({
    days: z.number().int(),
    count: z.number().int(),
    failedVerifications: z.number().int(),
    lastSignInAt: z.iso.datetime().nullable(),
  }),
});

export type ReviewAccountsResponse = z.infer<typeof ReviewAccountsResponseSchema>;
