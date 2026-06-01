/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { z } from 'zod';

import { RefreshSuccessResponseSchema } from './auth.responses.js';

export const PublicOAuthProviderSchema = z.object({
  id: z.string(),
  name: z.string(),
  scopes: z.array(z.string()),
});

export const OAuthProvidersResponseSchema = z.object({
  providers: z.array(PublicOAuthProviderSchema),
});

export const StartOAuthLoginResponseSchema = z.object({
  provider: PublicOAuthProviderSchema,
  state: z.string(),
  authorizationUrl: z.url(),
});

export const OAuthLoginSuccessResponseSchema = RefreshSuccessResponseSchema.omit({
  sessionId: true,
});
