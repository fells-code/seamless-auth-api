/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import type { Transaction } from 'sequelize';

import { Session } from '../models/sessions.js';
import { User } from '../models/users.js';

/**
 * Ends every session the given users hold, including one a refresh is creating right now.
 *
 * Reading the sessions and revoking them row by row left a gap: a refresh landing between
 * the read and the writes created a replacement nothing revoked. The bulk update closes
 * most of that, and the per-user cutoff closes the rest, because a session created at or
 * before it is refused wherever a session is accepted, whether or not its row was caught.
 *
 * The cutoff is written first so there is no moment where the rows are revoked and a
 * session minted from one of them still passes.
 */
export async function revokeAllSessionsForUsers(
  userIds: string | string[],
  reason: string,
  transaction?: Transaction,
): Promise<number> {
  const revokedAt = new Date();

  await User.update(
    { sessionsRevokedBefore: revokedAt },
    { where: { id: userIds }, ...(transaction ? { transaction } : {}) },
  );

  const [revoked] = await Session.update(
    { revokedAt, revokedReason: reason },
    { where: { userId: userIds, revokedAt: null }, ...(transaction ? { transaction } : {}) },
  );

  return revoked;
}

/**
 * Whether a revoke-all for the session's owner happened at or after the session began.
 * A session with no creation time is treated as revoked, so a malformed row fails closed.
 */
export function isRevokedByCutoff(
  session: Pick<Session, 'createdAt'>,
  sessionsRevokedBefore: Date | null | undefined,
): boolean {
  if (!sessionsRevokedBefore) return false;
  if (!session.createdAt) return true;

  return new Date(session.createdAt).getTime() <= new Date(sessionsRevokedBefore).getTime();
}
