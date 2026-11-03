/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { SendApplicationNoticeRequestSchema as BaseRequestSchema } from '@seamless-auth/types';
import { z } from 'zod';

// Mail and SMS clients turn a bare domain or an email address into a link as readily as a
// URL, so any of them is refused and `actionUrl`, checked against the client's origins,
// stays the only link a notice carries. Ideographic and fullwidth full stops count as dots
// because some clients link them too.
const SCHEME = /[\p{L}][\p{L}\p{N}+.-]*:\/\//iu;
const WWW = /(?<![\p{L}\p{N}-])www[.。．｡]/iu;
const HOSTNAME =
  /(?<![\p{L}\p{N}-])(?:[\p{L}\p{N}](?:[\p{L}\p{N}-]*[\p{L}\p{N}])?[.。．｡])+\p{L}{2,63}(?![\p{L}\p{N}-])/iu;

export function noticeTextHasLink(text: string) {
  return SCHEME.test(text) || WWW.test(text) || HOSTNAME.test(text);
}

// TODO(seamless-auth-types#148): move `clientId` to @seamless-auth/types.
export const SendApplicationNoticeRequestSchema = BaseRequestSchema.extend({
  text: BaseRequestSchema.shape.text.refine(
    (text) => !noticeTextHasLink(text),
    'Notice text must not contain links, domain names or email addresses. Put the one link in actionUrl.',
  ),
  /** A client the caller is linked to, to send for. The caller itself when omitted. */
  clientId: z.string().min(1).max(255).optional(),
});

export type SendApplicationNoticeRequest = z.infer<typeof SendApplicationNoticeRequestSchema>;
