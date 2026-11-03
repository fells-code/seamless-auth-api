/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { SendApplicationNoticeRequestSchema as BaseRequestSchema } from '@seamless-auth/types';
import { z } from 'zod';

// TODO(seamless-auth-types#148): move `clientId` to @seamless-auth/types.
export const SendApplicationNoticeRequestSchema = BaseRequestSchema.extend({
  /** A client the caller is linked to, to send for. The caller itself when omitted. */
  clientId: z.string().min(1).max(255).optional(),
});

export type SendApplicationNoticeRequest = z.infer<typeof SendApplicationNoticeRequestSchema>;
