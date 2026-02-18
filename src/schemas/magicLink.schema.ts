/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import { z } from 'zod';

export const MagicLinkRequestSchema = z.object({
  email: z.string().email(),
  redirect_url: z.string().optional(),
});

export const MagicLinkVerifyQuerySchema = z.object({
  token: z.string().min(32),
});
