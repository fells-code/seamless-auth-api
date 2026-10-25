/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import {
  AccountRecoveryChannelSchema,
  AccountRecoveryStateSchema,
  AccountRecoveryStatusSchema,
  AuthDeliverySchema,
} from '@seamless-auth/types';
import { z } from 'zod';

export {
  AccountRecoveryCancelRequestSchema,
  AccountRecoveryStartRequestSchema,
  AccountRecoveryStartResponseSchema,
  AccountRecoveryStatusSchema,
  AccountRecoveryVerifyRequestSchema,
} from '@seamless-auth/types';

export const AccountRecoveryRequestSchema = z.object({
  id: z.string().uuid(),
  channel: AccountRecoveryChannelSchema,
  state: AccountRecoveryStateSchema,
  requestedAt: z.string(),
  completesAt: z.string(),
});

export const AccountRecoveryRequestsResponseSchema = z.object({
  requests: z.array(AccountRecoveryRequestSchema),
});

export const AccountRecoveryRequestIdParamSchema = z.object({ id: z.string().uuid() });

/** `deliveries` only for a caller that named the notice kinds it delivers. */
export const AccountRecoveryVerifyResponseSchema = AccountRecoveryStatusSchema.extend({
  deliveries: z.array(AuthDeliverySchema).optional(),
});
