/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import getLogger from '../utils/logger.js';

const logger = getLogger('auditHealth');

/**
 * How long a write failure keeps the process reporting degraded.
 *
 * Long enough that an intermittent failure is still visible to a monitor that
 * scrapes health on a normal interval, short enough that a recovered instance
 * stops claiming to be degraded on its own.
 */
export const AUDIT_DEGRADED_WINDOW_MS = 5 * 60 * 1000;

let failureCount = 0;
let lastFailureAt: Date | null = null;

/**
 * Records that an audit write failed.
 *
 * NIST 800-53 AU-5 asks for a defined action on audit logging failure. Writing a
 * line to the application log is not one, because nothing reads it. This is the
 * state `/health/status` reports on, so a monitor already watching health sees an
 * instance that has stopped being able to record what it is doing.
 */
export function recordAuditWriteFailure(error: unknown, now = new Date()) {
  failureCount += 1;
  lastFailureAt = now;

  logger.error(
    `Audit write failed, reporting degraded for ${AUDIT_DEGRADED_WINDOW_MS / 1000}s. ` +
      `Total failures since start: ${failureCount}. Cause: ${error}`,
  );
}

export interface AuditHealth {
  degraded: boolean;
  failureCount: number;
  lastFailureAt: string | null;
}

export function getAuditHealth(now = new Date()): AuditHealth {
  const degraded =
    lastFailureAt !== null && now.getTime() - lastFailureAt.getTime() < AUDIT_DEGRADED_WINDOW_MS;

  return {
    degraded,
    failureCount,
    lastFailureAt: lastFailureAt ? lastFailureAt.toISOString() : null,
  };
}

/** Test seam. Process-level state has to be resettable between cases. */
export function resetAuditHealthForTests() {
  failureCount = 0;
  lastFailureAt = null;
}
