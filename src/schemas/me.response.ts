/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { CredentialApiSchema, UserSchema } from '@seamless-auth/types';
import { z } from 'zod';

export const MeResponseSchema = z.object({
  user: UserSchema.pick({
    id: true,
    email: true,
    phone: true,
    roles: true,
    lastLogin: true,
  }),
  credentials: z.array(CredentialApiSchema),
});
