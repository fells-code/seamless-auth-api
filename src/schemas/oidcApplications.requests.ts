/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import {
  OidcApplicationCreateRequestSchema as BaseCreateRequestSchema,
  OidcApplicationIdParamsSchema,
  OidcApplicationUpdateRequestSchema as BaseUpdateRequestSchema,
} from '@seamless-auth/types';
import { z } from 'zod';

// TODO(seamless-auth-types#148): move these to @seamless-auth/types.

const LOOPBACK_HOST = /^(127(\.\d{1,3}){3}|\[::1\]|localhost|.+\.localhost)$/i;

export function noticeActionOriginProblem(value: string): string | null {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return 'notice action origin must be an absolute https origin';
  }
  if (url.protocol !== 'https:') return 'notice action origins must be https';
  if (LOOPBACK_HOST.test(url.hostname)) return 'notice action origins cannot be loopback';
  if (url.origin !== value) {
    return 'notice action origins are bare origins, such as https://app.example.com';
  }
  return null;
}

export const NoticeActionOriginsSchema = z
  .array(
    z.string().superRefine((value, ctx) => {
      const problem = noticeActionOriginProblem(value);
      if (problem) ctx.addIssue({ code: 'custom', message: problem });
    }),
  )
  .max(20)
  .refine((origins) => new Set(origins).size === origins.length, {
    message: 'Origins must be unique',
  });

export const OidcApplicationCreateRequestSchema = BaseCreateRequestSchema.safeExtend({
  noticeActionOrigins: NoticeActionOriginsSchema.default([]),
});

export const OidcApplicationUpdateRequestSchema = BaseUpdateRequestSchema.extend({
  noticeActionOrigins: NoticeActionOriginsSchema.optional(),
});

export type OidcApplicationCreateRequest = z.infer<typeof OidcApplicationCreateRequestSchema>;
export type OidcApplicationUpdateRequest = z.infer<typeof OidcApplicationUpdateRequestSchema>;

export const OidcApplicationLinkParamsSchema = OidcApplicationIdParamsSchema.extend({
  linkedId: z.string().min(1).max(255),
});
