/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { z } from 'zod';

import { OAuthProviderConfigSchema } from './systemConfig.schema.js';

export const OAuthProvidersListResponseSchema = z.object({
  providers: z.array(OAuthProviderConfigSchema),
});

export const OAuthProviderResponseSchema = z.object({
  provider: OAuthProviderConfigSchema,
});

export const OAuthProviderDeletedResponseSchema = z.object({
  success: z.literal(true),
  id: z.string(),
});
