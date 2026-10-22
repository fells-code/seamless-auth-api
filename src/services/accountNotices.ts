/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import getLogger from '../utils/logger.js';
import { DeliveryError } from './deliveryError.js';
import type { IdentityNoticeStatus } from './identityChangeService.js';
import { sendNoticeEmail, sendNoticeSms } from './messagingService.js';

const logger = getLogger('accountNotices');

export interface NoticeRecipient {
  email: string | null;
  emailVerified?: boolean | null;
  phone: string | null;
  phoneVerified?: boolean | null;
}

export interface AccountNotice {
  subject: string;
  text: string;
}

export interface AccountNoticeResult {
  channel: 'email' | 'phone';
  status: IdentityNoticeStatus;
}

/** The account's verified addresses only: an unverified one may not be the owner's. */
export function verifiedAddresses(user: NoticeRecipient) {
  return {
    email: user.emailVerified && user.email ? user.email : null,
    phone: user.phoneVerified && user.phone ? user.phone : null,
  };
}

/**
 * Tells the owner, on every verified address, about something that happened to the
 * account. A notice that fails to send does not fail the request it reports on; the
 * outcome belongs in that request's audit event.
 *
 * `external` is for a credentialed caller that owns delivery. The delivery contract has
 * no kind for account notices, so such a caller cannot be handed one, and sending
 * directly would bypass it.
 */
export async function sendAccountNotice(
  user: NoticeRecipient,
  notice: AccountNotice,
  { external }: { external: boolean },
): Promise<AccountNoticeResult[]> {
  const { email, phone } = verifiedAddresses(user);
  const targets: Array<['email' | 'phone', string | null]> = [
    ['email', email],
    ['phone', phone],
  ];
  const results: AccountNoticeResult[] = [];

  for (const [channel, to] of targets) {
    if (!to) continue;

    if (external) {
      results.push({ channel, status: 'not_sent_external_delivery' });
      continue;
    }

    try {
      if (channel === 'email') {
        await sendNoticeEmail(to, notice.subject, notice.text);
      } else {
        await sendNoticeSms(to, notice.text);
      }
      results.push({ channel, status: 'sent' });
    } catch (error) {
      if (!(error instanceof DeliveryError)) throw error;
      logger.error(`Account notice failed on ${channel}`);
      results.push({ channel, status: 'failed' });
    }
  }

  return results;
}
