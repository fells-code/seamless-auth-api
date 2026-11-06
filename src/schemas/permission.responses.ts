/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { z } from 'zod';

export {
  EffectivePermissionsResponseSchema,
  PermissionEnvelopeResponseSchema,
  PermissionListResponseSchema,
  RoleEnvelopeResponseSchema,
  RoleListResponseSchema,
} from '@seamless-auth/types';

/** Local because only this server's refusals name what stood in the way. */
export const PermissionConflictErrorSchema = z.object({
  error: z.string(),
  details: z.record(z.string(), z.unknown()).optional(),
});
