/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { z } from 'zod';

import { assertValidPrfSalt } from '../lib/webauthnPrf.js';

const BooleanQuerySchema = z.preprocess((value) => {
  if (value === 'true') return true;
  if (value === 'false') return false;
  return value;
}, z.boolean().optional());

export const WebAuthnPrfRequestSchema = z.object({
  salt: z.string().superRefine((value, ctx) => {
    try {
      assertValidPrfSalt(value);
    } catch (error) {
      ctx.addIssue({
        code: 'custom',
        message: error instanceof Error ? error.message : 'Invalid PRF salt',
      });
    }
  }),
  secondSalt: z
    .string()
    .superRefine((value, ctx) => {
      try {
        assertValidPrfSalt(value);
      } catch (error) {
        ctx.addIssue({
          code: 'custom',
          message: error instanceof Error ? error.message : 'Invalid PRF salt',
        });
      }
    })
    .optional(),
});

export const WebAuthnRegisterStartQuerySchema = z.object({
  requestPrf: BooleanQuerySchema,
  requirePrf: BooleanQuerySchema,
});

export const WebAuthnAssertionStartSchema = z
  .object({
    credentialId: z.string().optional(),
    prf: WebAuthnPrfRequestSchema.optional(),
  })
  .default({});

export const WebAuthnRegisterFinishSchema = z.object({
  attestationResponse: z.record(z.string(), z.unknown()),

  metadata: z
    .object({
      friendlyName: z.string().optional(),
      platform: z.string().optional(),
      browser: z.string().optional(),
      deviceInfo: z.string().optional(),
      prfCapable: z.boolean().optional(),
    })
    .optional(),
});

export const WebAuthnLoginFinishSchema = z.object({
  assertionResponse: z.record(z.string(), z.unknown()),
});
