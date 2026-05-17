/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { z } from 'zod';

export const TotpStatusSchema = z.object({
  enabled: z.boolean(),
  verifiedAt: z.string().nullable(),
  lastUsedAt: z.string().nullable(),
});

export const TotpEnrollmentStartSchema = z.object({
  message: z.string(),
  secret: z.string(),
  otpauthUrl: z.string(),
  issuer: z.string(),
  accountName: z.string(),
  algorithm: z.literal('SHA1'),
  digits: z.number(),
  period: z.number(),
});

export const TotpVerifySuccessSchema = z.object({
  message: z.string(),
});
