/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { QueryTypes } from 'sequelize';

import { REVIEW_ACCOUNT_METADATA_KEY, reviewAccountSettings } from '../lib/reviewAccounts.js';
import { getSequelize } from '../models/index.js';
import type { AuthEventType } from '../schemas/authEvent.types.js';
import type { ReviewAccountsQuery, ReviewAccountsResponse } from '../schemas/reviewAccounts.js';

const DAY_MS = 24 * 60 * 60 * 1000;
const SUCCESS_TYPE: AuthEventType = 'verify_otp_success';
const FAILED_TYPE: AuthEventType = 'verify_otp_failed';

interface UsageRow {
  signIns: number | string | null;
  failedVerifications: number | string | null;
  lastSignInAt: Date | string | null;
}

/**
 * A completed code sign-in writes `verify_otp_success` twice, so sign-ins are folded by
 * attempt, the same way the sign-in metrics fold them. A row with no attempt id stands
 * alone. Failures are counted per event: each one is a wrong guess at a code that does
 * not rotate.
 */
async function recentUsage(days: number, now: Date) {
  const [row] = await getSequelize().query<UsageRow>(
    `
    SELECT COUNT(DISTINCT COALESCE(attempt_id::text, id::text))
             FILTER (WHERE type = :successType)::int AS "signIns",
           COUNT(*) FILTER (WHERE type = :failedType)::int AS "failedVerifications",
           MAX(created_at) FILTER (WHERE type = :successType) AS "lastSignInAt"
    FROM auth_events
    WHERE type IN (:successType, :failedType)
      AND created_at >= :since
      AND metadata ->> :flagKey = 'true'
    `,
    {
      replacements: {
        successType: SUCCESS_TYPE,
        failedType: FAILED_TYPE,
        since: new Date(now.getTime() - days * DAY_MS),
        flagKey: REVIEW_ACCOUNT_METADATA_KEY,
      },
      type: QueryTypes.SELECT,
    },
  );

  return {
    days,
    count: Number(row?.signIns ?? 0),
    failedVerifications: Number(row?.failedVerifications ?? 0),
    lastSignInAt: row?.lastSignInAt ? new Date(row.lastSignInAt).toISOString() : null,
  };
}

export async function getReviewAccounts(
  { days }: ReviewAccountsQuery,
  now: Date = new Date(),
): Promise<ReviewAccountsResponse> {
  return { ...reviewAccountSettings(), recentSignIns: await recentUsage(days, now) };
}
