/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import {
  CustomClaimListResponseSchema as SharedListResponseSchema,
  CustomClaimSetSchema,
  CustomClaimSourceResponseSchema as SharedSourceResponseSchema,
  CustomClaimSourceSchema as SharedSourceSchema,
} from '@seamless-auth/types';
import { z } from 'zod';

export { CustomClaimSourceParamSchema } from '@seamless-auth/types';

/**
 * The shared schemas type claim values as `z.json()`, which is recursive, and the OpenAPI
 * generator overflows its stack on it. These keep the shared validation and describe a value
 * as any JSON for the document.
 */
const ClaimSetSchema = z.record(z.string(), z.unknown()).superRefine((claims, ctx) => {
  const parsed = CustomClaimSetSchema.safeParse(claims);
  if (parsed.success) return;
  for (const issue of parsed.error.issues) {
    ctx.addIssue({ code: 'custom', message: issue.message, path: issue.path });
  }
});

export const SetCustomClaimsRequestSchema = z.object({ claims: ClaimSetSchema });

const CustomClaimSourceSchema = SharedSourceSchema.extend({
  claims: z.record(z.string(), z.unknown()),
});

export const CustomClaimSourceResponseSchema = SharedSourceResponseSchema.extend({
  source: CustomClaimSourceSchema,
});

export const CustomClaimListResponseSchema = SharedListResponseSchema.extend({
  sources: z.array(CustomClaimSourceSchema),
});
