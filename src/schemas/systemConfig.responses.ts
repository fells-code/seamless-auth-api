/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { z } from 'zod';

export {
  AvailableRolesResponseSchema,
  GetSystemConfigResponseSchema,
  PublicSystemConfigResponseSchema,
  UpdateSystemConfigResponseSchema,
} from '@seamless-auth/types';

// The shared package models this as the generic error envelope. It stays local so the
// system-config routes keep declaring the exact body their handlers return.
export const InvalidPayloadSchema = z.object({
  error: z.string(),
  details: z.unknown().optional(),
});
