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
 * A link opened on a device other than the one that asked for it. The link is still
 * unused; confirming it from this device signs the requesting device in.
 */
export const MagicLinkConfirmationRequiredSchema = z.object({
  error: z.literal('confirmation_required'),
  message: z.string(),
  requestedFrom: z.object({
    deviceClass: z.enum(DEVICE_CLASSES),
    requestedAt: z.string(),
  }),
});
