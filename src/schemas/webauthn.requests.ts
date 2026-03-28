/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { z } from 'zod';

export const WebAuthnRegisterFinishSchema = z.object({
  attestationResponse: z.record(z.string(), z.unknown()),

  metadata: z
    .object({
      friendlyName: z.string().optional(),
      platform: z.string().optional(),
      browser: z.string().optional(),
      deviceInfo: z.string().optional(),
    })
    .optional(),
});

export const WebAuthnLoginFinishSchema = z.object({
  assertionResponse: z.record(z.string(), z.unknown()),
});
