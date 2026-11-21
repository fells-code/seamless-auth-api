/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import getLogger from '../utils/logger.js';

const logger = getLogger('unauthenticatedRefusals');

export type UnauthenticatedRefusal =
  'cors_origin_refused' | 'unknown_route' | 'refresh_token_missing' | 'refresh_token_unknown';

/** How often the counts are written to the application log, at most. */
export const REFUSAL_SUMMARY_INTERVAL_MS = 60 * 1000;

let counts = new Map<UnauthenticatedRefusal, number>();
let windowStartedAt = Date.now();

function flush(now: number) {
  const summary = [...counts.entries()].map(([kind, count]) => `${kind}=${count}`).join(' ');

  logger.warn(
    `Unauthenticated refusals in the last ${Math.round((now - windowStartedAt) / 1000)}s: ${summary}`,
  );

  counts = new Map();
  windowStartedAt = now;
}

/**
 * Counts a refusal that any caller can produce for nothing: an origin that is not allowed,
 * a route that does not exist, or a refresh token that is missing or matches no session.
 *
 * These used to be audit events. Each one took the audit chain head lock and added a
 * permanent row, so a scanner at the general rate limit could grow the trail and queue
 * real sign-ins behind its writes. A count in the application log keeps the signal for
 * monitoring without either cost. See "Refusals at the auth gate" in
 * docs/security-posture.md.
 */
export function countUnauthenticatedRefusal(kind: UnauthenticatedRefusal, now = Date.now()) {
  counts.set(kind, (counts.get(kind) ?? 0) + 1);

  if (now - windowStartedAt >= REFUSAL_SUMMARY_INTERVAL_MS) {
    flush(now);
  }
}

export function getUnauthenticatedRefusalCounts(): Partial<Record<UnauthenticatedRefusal, number>> {
  return Object.fromEntries(counts);
}

/** Test seam. Process-level state has to be resettable between cases. */
export function resetUnauthenticatedRefusalsForTests(now = Date.now()) {
  counts = new Map();
  windowStartedAt = now;
}
