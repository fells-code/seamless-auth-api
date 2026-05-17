/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { z } from 'zod';

export const StepUpStatusSchema = z.object({
  fresh: z.boolean(),
  method: z.enum(['webauthn', 'totp']).nullable(),
  verifiedAt: z.string().nullable(),
  expiresAt: z.string().nullable(),
  maxAgeSeconds: z.number(),
});

export const StepUpSuccessSchema = z.object({
  message: z.string(),
  fresh: z.boolean(),
  method: z.enum(['webauthn', 'totp']),
  verifiedAt: z.string(),
  expiresAt: z.string(),
  maxAgeSeconds: z.number(),
});
