/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { CredentialApiSchema } from '@seamless-auth/types';
import { z } from 'zod';

export const CredentialResponseSchema = CredentialApiSchema.extend({
  backedup: z.boolean(),
  backedUp: z.boolean(),
  prfCapable: z.boolean().optional(),
});

export const CredentialUpdateResponseSchema = z.object({
  message: z.string(),
  credential: CredentialResponseSchema,
});
