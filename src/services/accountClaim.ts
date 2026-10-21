/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import type { User } from '../models/users.js';

/**
 * Marks an unverified account as claimed by the attempt that just proved its email
 * address. Does not save.
 *
 * Anyone can start a registration for an address and verify a phone on the account it
 * creates, so a phone verified before the address was proven only stays if the same
 * attempt verified it. Phone-first sign up does exactly that; a phone planted through an
 * earlier attempt by someone else does not. Every route that proves the address and
 * completes registration must go through here, or it keeps the planted phone.
 */
export function claimUnverifiedAccount(user: User, attemptId?: string): boolean {
  if (user.verified) return false;

  user.verified = true;
  user.emailVerified = true;
  user.emailVerificationToken = null;
  user.emailVerificationTokenExpiry = null;

  if (user.phoneVerified && (!attemptId || user.phoneVerifiedAttemptId !== attemptId)) {
    user.phone = null;
    user.phoneVerified = false;
    user.phoneVerificationToken = null;
    user.phoneVerificationTokenExpiry = null;
  }
  user.phoneVerifiedAttemptId = null;

  return true;
}
