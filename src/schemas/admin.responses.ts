/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { z } from 'zod';

export {
  AdminUserAnomaliesResponseSchema,
  AdminUserDetailResponseSchema,
  DeviceReplacementRecoveryResponseSchema,
  ImportUsersResponseSchema,
  UserResponseSchema,
} from '@seamless-auth/types';

// Validation failures on the user endpoints carry a `details` payload naming what was
// rejected, which a plain error schema would strip before it reached the caller.
export const AdminValidationErrorSchema = z.object({
  error: z.string(),
  message: z.string().optional(),
  details: z.record(z.string(), z.unknown()).optional(),
});

export const AuditIntegrityResponseSchema = z.object({
  verified: z.boolean(),
  checkedAt: z.string(),
  rowsChecked: z.number().int(),
  firstSeq: z.number().int().nullable(),
  lastSeq: z.number().int().nullable(),
  anchorHash: z.string().nullable(),
  head: z.object({ seq: z.number().int(), hash: z.string().nullable() }).nullable(),
  firstFailure: z
    .object({
      seq: z.number().int(),
      id: z.string().nullable(),
      reason: z.enum(['hash_mismatch', 'broken_link', 'sequence_gap', 'head_mismatch']),
    })
    .nullable(),
});
