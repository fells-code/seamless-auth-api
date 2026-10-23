/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import type { Transaction } from 'sequelize';

import { getSystemConfig } from '../config/getSystemConfig.js';
import getLogger from '../utils/logger.js';
import { hashSha256 } from '../utils/utils.js';
import { DeliveryError } from './deliveryError.js';
import { sendNoticeEmail, sendNoticeSms } from './messagingService.js';
import { revokeAllSessionsForUsers } from './sessionRevocation.js';

const logger = getLogger('identityChange');

export type IdentityField = 'email' | 'phone';

export interface IdentityChange {
  field: IdentityField;
  previous: string | null;
  next: string | null;
}

export type IdentityNoticeStatus = 'sent' | 'failed' | 'not_sent_external_delivery';

export interface IdentityNoticeResult {
  field: IdentityField;
  recipient: 'previous' | 'new';
  status: IdentityNoticeStatus;
}

function sameEmail(a: string | null, b: string | null) {
  return (a ?? '').toLowerCase() === (b ?? '').toLowerCase();
}

export function detectIdentityChanges(
  current: { email: string | null; phone: string | null },
  update: Record<string, unknown>,
): IdentityChange[] {
  const changes: IdentityChange[] = [];

  if (typeof update.email === 'string' && !sameEmail(current.email, update.email)) {
    changes.push({ field: 'email', previous: current.email, next: update.email });
  }

  if ('phone' in update) {
    const next = typeof update.phone === 'string' ? update.phone : null;

    if (next !== (current.phone ?? null)) {
      changes.push({ field: 'phone', previous: current.phone ?? null, next });
    }
  }

  return changes;
}

/**
 * Audit metadata is redacted of addresses before it is stored, so the values are kept
 * as digests of the normalized form. An investigator can still confirm whether a given
 * address was the one removed or added.
 */
export function auditIdentityChanges(changes: IdentityChange[]) {
  const digest = (field: IdentityField, value: string | null) =>
    value === null ? null : hashSha256(field === 'email' ? value.toLowerCase() : value);

  return changes.map(({ field, previous, next }) => ({
    field,
    previousSha256: digest(field, previous),
    nextSha256: digest(field, next),
  }));
}

export async function revokeSessionsForIdentityChange(
  userId: string,
  transaction?: Transaction,
): Promise<number> {
  return revokeAllSessionsForUsers(userId, 'admin_identity_change', transaction);
}

function noticeText(appName: string, field: IdentityField, recipient: 'previous' | 'new') {
  const label = field === 'email' ? 'email address' : 'phone number';

  if (recipient === 'previous') {
    return `An administrator changed the ${label} on your ${appName} account, and every session on it was signed out. If you did not expect this change, contact your administrator.`;
  }

  return `An administrator set this ${label} on an ${appName} account. If you did not expect this, contact your administrator.`;
}

async function deliver(
  field: IdentityField,
  to: string,
  appName: string,
  recipient: 'previous' | 'new',
) {
  const text = noticeText(appName, field, recipient);

  if (field === 'email') {
    await sendNoticeEmail(to, `Your ${appName} sign-in email was changed`, text);
  } else {
    await sendNoticeSms(to, text);
  }
}

/**
 * A notice that fails to send does not undo the change or fail the request: the change
 * is already stored and the sessions are already revoked, so the outcome is recorded in
 * the audit event instead.
 */
export async function sendIdentityChangeNotices(
  changes: IdentityChange[],
  { external }: { external: boolean },
): Promise<IdentityNoticeResult[]> {
  const results: IdentityNoticeResult[] = [];
  const appName = (await getSystemConfig())?.app_name ?? 'Seamless Auth';

  for (const change of changes) {
    const targets: Array<['previous' | 'new', string | null]> = [
      ['previous', change.previous],
      ['new', change.next],
    ];

    for (const [recipient, to] of targets) {
      if (!to) continue;

      // The delivery contract has no kind for account notices, so a caller that owns
      // delivery cannot be handed one. Sending directly would bypass that caller.
      if (external) {
        results.push({ field: change.field, recipient, status: 'not_sent_external_delivery' });
        continue;
      }

      try {
        await deliver(change.field, to, appName, recipient);
        results.push({ field: change.field, recipient, status: 'sent' });
      } catch (error) {
        if (!(error instanceof DeliveryError)) throw error;
        logger.error(`Identity change notice failed for ${change.field} (${recipient})`);
        results.push({ field: change.field, recipient, status: 'failed' });
      }
    }
  }

  return results;
}
