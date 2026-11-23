/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { MagicLinkPollSuccessSchema } from '@seamless-auth/types';
import z from 'zod';

import { DEVICE_CLASSES } from '../lib/deviceClass.js';

export { MagicLinkPollSuccessSchema };

/** A confirmed link whose session this attempt has already collected. */
export const MagicLinkPollRedeemedSchema = z.object({
  message: z.literal('Success'),
});

export const MagicLinkPollResponseSchema = z.union([
  MagicLinkPollSuccessSchema,
  MagicLinkPollRedeemedSchema,
]);

/**
 * Every open of a link answers this, and the link stays unused until it is confirmed
 * with the code from its fragment. `sameDevice` says whether it was opened by the
 * attempt that requested it, so a client can confirm without asking when it was.
 */
export const MagicLinkConfirmationRequiredSchema = z.object({
  error: z.literal('confirmation_required'),
  message: z.string(),
  sameDevice: z.boolean(),
  requestedFrom: z.object({
    deviceClass: z.enum(DEVICE_CLASSES),
    requestedAt: z.string(),
  }),
});
