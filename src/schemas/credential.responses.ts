/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { CredentialApiSchema } from '@seamless-auth/types';
import { z } from 'zod';

import { AUTHENTICATOR_TRANSPORTS } from '../lib/authenticatorTransports.js';

export const CredentialResponseSchema = CredentialApiSchema.extend({
  backedup: z.boolean(),
  backedUp: z.boolean(),
  prfCapable: z.boolean().optional(),
  // `CredentialApiSchema` in @seamless-auth/types@0.1.3 still declares the pre-hybrid
  // four-value transport set. Drop this override once the widened release is adopted.
  transports: z.array(z.enum(AUTHENTICATOR_TRANSPORTS)).optional(),
});

export const CredentialUpdateResponseSchema = z.object({
  message: z.string(),
  credential: CredentialResponseSchema,
});
