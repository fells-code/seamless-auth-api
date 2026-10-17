/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { MagicLinkPollSuccessSchema } from '@seamless-auth/types';
import z from 'zod';

export { MagicLinkPollSuccessSchema };

/** A confirmed link whose session this attempt has already collected. */
export const MagicLinkPollRedeemedSchema = z.object({
  message: z.literal('Success'),
});

export const MagicLinkPollResponseSchema = z.union([
  MagicLinkPollSuccessSchema,
  MagicLinkPollRedeemedSchema,
]);
