/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { z } from 'zod';

import { OAuthProviderConfigSchema } from './systemConfig.schema.js';

export const OAuthProviderCreateSchema = OAuthProviderConfigSchema;

export const OAuthProviderIdParamSchema = z.object({
  id: z.string().regex(/^[a-z0-9-]{2,40}$/),
});

// The id is immutable and taken from the path, so it is omitted here. Every other
// field is optional so callers can patch a single attribute without resending the
// whole provider; the merged result is re-validated against the full schema.
export const OAuthProviderUpdateSchema = OAuthProviderConfigSchema.omit({ id: true })
  .partial()
  .strict();
