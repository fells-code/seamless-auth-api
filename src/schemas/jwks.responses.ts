/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { z } from 'zod';

export const JWKSchema = z.object({
  kty: z.string(),
  kid: z.string(),
  use: z.string(),
  alg: z.string(),

  n: z.string().optional(),
  e: z.string().optional(),

  x: z.string().optional(),
  y: z.string().optional(),
  crv: z.string().optional(),
});

export const JWKSResponseSchema = z.object({
  keys: z.array(JWKSchema),
});

export const JWKSErrorSchema = z.object({
  error: z.string(),
});
