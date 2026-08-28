/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import {
  WebAuthnAssertionStartSchema as SharedAssertionStartSchema,
  WebAuthnPrfRequestSchema as SharedPrfRequestSchema,
  WebAuthnRegisterStartQuerySchema as SharedRegisterStartQuerySchema,
} from '@seamless-auth/types';
import { z } from 'zod';

import { assertValidPrfSalt } from '../lib/webauthnPrf.js';

export { WebAuthnLoginFinishSchema, WebAuthnRegisterFinishSchema } from '@seamless-auth/types';

function checkSalt(value: string | undefined, ctx: z.RefinementCtx, path: string) {
  if (value === undefined) return;

  try {
    assertValidPrfSalt(value);
  } catch (error) {
    ctx.addIssue({
      code: 'custom',
      path: [path],
      message: error instanceof Error ? error.message : 'Invalid PRF salt',
    });
  }
}

/**
 * The shared schema asserts the wire shape only. PRF salts also have to satisfy this
 * server's own rules (length and encoding), which `assertValidPrfSalt` owns, so the
 * runtime check is layered on top rather than duplicated into the shared contract.
 */
export const WebAuthnPrfRequestSchema = SharedPrfRequestSchema.superRefine((value, ctx) => {
  checkSalt(value.salt, ctx, 'salt');
  checkSalt(value.secondSalt, ctx, 'secondSalt');
});

// Rebuilt rather than re-exported: the shared version embeds the unvalidated PRF schema.
// It ships wrapped in a default, so unwrap before swapping the field back in.
export const WebAuthnAssertionStartSchema = SharedAssertionStartSchema.unwrap()
  .extend({ prf: WebAuthnPrfRequestSchema.optional() })
  .default({});

/**
 * Which kind of authenticator the browser should offer at registration. Omitting it
 * offers both, which is what a deployment that issues hardware security keys needs;
 * naming one narrows the picker to that kind.
 */
export const WebAuthnAuthenticatorAttachmentSchema = z.enum(['platform', 'cross-platform']);

export type WebAuthnAuthenticatorAttachment = z.infer<typeof WebAuthnAuthenticatorAttachmentSchema>;

// Extended rather than re-exported: the shared query schema covers the PRF flags only.
export const WebAuthnRegisterStartQuerySchema = SharedRegisterStartQuerySchema.extend({
  attachment: WebAuthnAuthenticatorAttachmentSchema.optional(),
});
