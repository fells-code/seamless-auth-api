/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { UserSchema } from '@seamless-auth/types';
import { z } from 'zod';

export const UserResponseSchema = z.object({
  user: UserSchema,
});
