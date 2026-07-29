/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { z } from 'zod';

export {
  AdminUserAnomaliesResponseSchema,
  AdminUserDetailResponseSchema,
  DeviceReplacementRecoveryResponseSchema,
  UserResponseSchema,
} from '@seamless-auth/types';

// Validation failures on the user endpoints carry a `details` payload naming what was
// rejected, which a plain error schema would strip before it reached the caller.
export const AdminValidationErrorSchema = z.object({
  error: z.string(),
  message: z.string().optional(),
  details: z.record(z.string(), z.unknown()).optional(),
});
