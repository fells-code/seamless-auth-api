/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { AuthEventSchema, SessionSchema } from '@seamless-auth/types';
import { z } from 'zod';

import { CredentialResponseSchema } from './credential.responses.js';
import { ApiUserSchema } from './user.schema.js';

export const UserResponseSchema = z.object({
  user: ApiUserSchema,
});

export const DeviceReplacementRecoveryResponseSchema = z.object({
  userId: z.string(),
  revokedSessions: z.number().int().nonnegative(),
  removedCredentials: z.number().int().nonnegative(),
  disabledTotpCredentials: z.number().int().nonnegative(),
});

export const AdminUserDetailResponseSchema = z.object({
  user: ApiUserSchema,
  sessions: z.array(SessionSchema),
  credentials: z.array(CredentialResponseSchema),
  events: z.array(AuthEventSchema),
});

export const AdminUserAnomaliesResponseSchema = z.object({
  suspiciousEvents: z.array(AuthEventSchema),
  relatedIps: z.array(z.string()),
  relatedAgents: z.array(z.string()),
});

// Validation failures on the user endpoints carry a `details` payload naming what was
// rejected, which a plain error schema would strip before it reached the caller.
export const AdminValidationErrorSchema = z.object({
  error: z.string(),
  message: z.string().optional(),
  details: z.record(z.string(), z.unknown()).optional(),
});
