/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import type {
  AccountNoticeApplication,
  AccountNoticeName,
  AuthDeliveryInstruction,
} from '@seamless-auth/types';

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
  name: AccountNoticeName;
  subject: string;
  text: string;
  cancelUrl?: string;
  application?: AccountNoticeApplication;
}

export interface AccountNoticeResult {
  channel: 'email' | 'phone';
  status: IdentityNoticeStatus | 'returned_for_external_delivery';
}

export interface AccountNoticeOutcome {
  results: AccountNoticeResult[];
  /** For the caller to deliver; they can carry a credential, so never log them. */
  deliveries: AuthDeliveryInstruction[];
}

/** Whether the owner was told, or the notice was handed to a caller that delivers it. */
export function ownerWasNotified({ results }: AccountNoticeOutcome) {
  return results.some(
    ({ status }) => status === 'sent' || status === 'returned_for_external_delivery',
  );
}

function asDelivery(
  notice: AccountNotice,
  channel: 'email' | 'phone',
  to: string,
): AuthDeliveryInstruction {
  const cancelUrl = {
    ...(notice.cancelUrl ? { cancelUrl: notice.cancelUrl } : {}),
    ...(notice.application ? { application: notice.application } : {}),
  };

  return channel === 'email'
    ? {
        kind: 'account_notice_email',
        notice: notice.name,
        to,
        subject: notice.subject,
        text: notice.text,
        ...cancelUrl,
      }
    : { kind: 'account_notice_sms', notice: notice.name, to, text: notice.text, ...cancelUrl };
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
 * `external` is for a credentialed caller that owns delivery, so the API does not send
 * for it. A route that can return notices passes the kinds that caller accepts as
 * `returnable`; a notice of any other kind is not sent at all.
 */
export async function sendAccountNotice(
  user: NoticeRecipient,
  notice: AccountNotice,
  { external, returnable }: { external: boolean; returnable?: ReadonlySet<string> },
): Promise<AccountNoticeOutcome> {
  const { email, phone } = verifiedAddresses(user);
  const targets: Array<['email' | 'phone', string | null]> = [
    ['email', email],
    ['phone', phone],
  ];
  const results: AccountNoticeResult[] = [];
  const deliveries: AuthDeliveryInstruction[] = [];

  for (const [channel, to] of targets) {
    if (!to) continue;

    if (external) {
      const delivery = asDelivery(notice, channel, to);

      if (returnable?.has(delivery.kind)) {
        deliveries.push(delivery);
        results.push({ channel, status: 'returned_for_external_delivery' });
      } else {
        results.push({ channel, status: 'not_sent_external_delivery' });
      }
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

  return { results, deliveries };
}
