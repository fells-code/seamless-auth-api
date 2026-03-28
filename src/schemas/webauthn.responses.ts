/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { z } from 'zod';

export const WebAuthnChallengeSchema = z.record(z.string(), z.unknown());

export const WebAuthnTokenSuccessSchema = z.object({
  message: z.string(),
  token: z.string().optional(),
  refreshToken: z.string().optional(),
  refreshTokenHash: z.string().optional(),

  sub: z.string().optional(),
  roles: z.array(z.string()).optional(),
  email: z.string().optional(),
  phone: z.string().nullable().optional(),

  ttl: z.number().optional(),
  refreshTtl: z.number().optional(),
});
