/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import type { Session } from '../models/sessions.js';

export type RefreshRefusalReason = 'absolute_lifetime_reached' | 'idle_timeout';

/**
 * Why an unrotated session can no longer be refreshed: revoked, or out of time. `null` means
 * it can be.
 */
export function classifyRefreshRefusal(
  session: Pick<Session, 'revokedAt' | 'expiresAt' | 'idleExpiresAt'>,
  now = new Date(),
): RefreshRefusalReason | 'revoked' | null {
  if (session.revokedAt) return 'revoked';
  if (session.expiresAt <= now) return 'absolute_lifetime_reached';
  if (session.idleExpiresAt <= now) return 'idle_timeout';

  return null;
}
