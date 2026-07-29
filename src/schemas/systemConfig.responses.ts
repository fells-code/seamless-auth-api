/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { z } from 'zod';

export {
  AvailableRolesResponseSchema,
  GetSystemConfigResponseSchema,
  UpdateSystemConfigResponseSchema,
} from '@seamless-auth/types';

// The shared package models these as the generic error envelope. They stay local so the
// system-config routes keep declaring the exact bodies their handlers return.
export const UnauthorizedSchema = z.object({
  error: z.string(),
});

export const InvalidPayloadSchema = z.object({
  error: z.string(),
  details: z.unknown().optional(),
});

export const SystemConfigErrorSchema = z.object({
  error: z.string(),
});
