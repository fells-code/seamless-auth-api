/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { z } from 'zod';

export const OAuthProviderParamSchema = z.object({
  providerId: z.string().regex(/^[a-z0-9-]{2,40}$/),
});

export const StartOAuthLoginRequestSchema = z.object({
  redirectUri: z.url().optional(),
  returnTo: z.url().optional(),
});

export const FinishOAuthLoginRequestSchema = z.object({
  code: z.string().trim().min(1),
  state: z.string().trim().min(1),
});
