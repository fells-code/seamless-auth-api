/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { QueryTypes } from 'sequelize';

import { getSequelize } from '../models/index.js';
import { SIGN_IN_SUCCESS_TYPES } from '../schemas/authEvent.types.js';

export interface FunnelWindow {
  from?: Date;
  to?: Date;
}

export interface IntervalStats {
  /** How many intervals the percentiles were computed over. */
  count: number;
  medianSeconds: number | null;
  p90Seconds: number | null;
}

export interface PasskeyAdoption {
  users: number;
  withPasskey: number;
  rate: number;
}

export interface FunnelMetrics {
  timeToRegistration: IntervalStats;
  timeToLogin: IntervalStats;
  passkeyAdoption: PasskeyAdoption;
  timeToFirstPasskey: IntervalStats;
}

/**
 * How long a completed sign-in may trail the `login_success` that started it. Matches
 * the ephemeral token TTL in `signEphemeralToken`: a factor cannot be proven on an
 * expired token, so a later sign-in belongs to a later attempt.
 */
const LOGIN_ATTEMPT_WINDOW = '5 minutes';

type IntervalRow = {
  count: string | number;
  median_seconds: string | number | null;
  p90_seconds: string | number | null;
};

type AdoptionRow = IntervalRow & {
  users: string | number;
};

function toNumber(value: string | number | null | undefined): number | null {
  if (value === null || value === undefined) return null;

  const parsed = Number(value);

  return Number.isFinite(parsed) ? parsed : null;
}

// Millisecond precision. A passkey sign-in can complete inside a second, so whole
// seconds would flatten the fastest path to zero, and anything finer is noise.
function toSeconds(value: string | number | null | undefined): number | null {
  const parsed = toNumber(value);

  return parsed === null ? null : Math.round(parsed * 1000) / 1000;
}

function toIntervalStats(row: IntervalRow | undefined): IntervalStats {
  return {
    count: toNumber(row?.count) ?? 0,
    medianSeconds: toSeconds(row?.median_seconds),
    p90Seconds: toSeconds(row?.p90_seconds),
  };
}

// Aggregates in seconds rather than an interval, so the driver hands back a number
// and not a string that would need parsing.
const PERCENTILES = (expression: string) => `
  COUNT(*) AS count,
  percentile_cont(0.5) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (${expression}))) AS median_seconds,
  percentile_cont(0.9) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (${expression}))) AS p90_seconds
`;

function windowClause(column: string, window: FunnelWindow) {
  const clauses: string[] = [];

  if (window.from) clauses.push(`${column} >= :from`);
  if (window.to) clauses.push(`${column} <= :to`);

  return clauses.length ? `AND ${clauses.join(' AND ')}` : '';
}

async function selectOne<T extends object>(sql: string, replacements: Record<string, unknown>) {
  const rows = await getSequelize().query<T>(sql, { replacements, type: QueryTypes.SELECT });

  return rows[0];
}

/**
 * Account created to first completed sign-in, per user.
 *
 * The cohort is anchored on the `user_created` event rather than `users.created_at`, so
 * that only self-serve registrations count. Accounts an administrator or an OAuth
 * sign-up creates never emit it, and neither goes through the registration funnel.
 */
async function timeToRegistration(window: FunnelWindow) {
  const row = await selectOne<IntervalRow>(
    `
    WITH created AS (
      SELECT user_id, MIN(created_at) AS created_at
      FROM auth_events
      WHERE type = 'user_created'
        AND user_id IS NOT NULL
        ${windowClause('created_at', window)}
      GROUP BY user_id
    ),
    completed AS (
      SELECT c.created_at, MIN(e.created_at) AS signed_in_at
      FROM created c
      JOIN auth_events e
        ON e.user_id = c.user_id
       AND e.type IN (:signInTypes)
       AND e.created_at >= c.created_at
      GROUP BY c.user_id, c.created_at
    )
    SELECT ${PERCENTILES('signed_in_at - created_at')}
    FROM completed
    `,
    { ...window, signInTypes: [...SIGN_IN_SUCCESS_TYPES] },
  );

  return toIntervalStats(row);
}

/**
 * `login_success` to the completed sign-in it led to, per attempt.
 *
 * There is no flow id to join on: the ephemeral token carries no `jti` and
 * `session_id` is null until a session exists. So an attempt is bracketed by user and
 * time instead. The first completed sign-in after a `login_success`, within the
 * ephemeral TTL and before that user's next `login_success`, is taken as its outcome.
 * A retried attempt therefore counts once, against the `login_success` it completed.
 *
 * OAuth is excluded. `oauth_login_started` carries no user id, since the account may
 * not exist yet, so its attempts cannot be bracketed the same way.
 */
async function timeToLogin(window: FunnelWindow) {
  const row = await selectOne<IntervalRow>(
    `
    WITH attempts AS (
      SELECT user_id,
             created_at AS started_at,
             LEAD(created_at) OVER (PARTITION BY user_id ORDER BY created_at) AS next_started_at
      FROM auth_events
      WHERE type = 'login_success'
        AND user_id IS NOT NULL
        ${windowClause('created_at', window)}
    ),
    completed AS (
      SELECT a.started_at, MIN(e.created_at) AS completed_at
      FROM attempts a
      JOIN auth_events e
        ON e.user_id = a.user_id
       AND e.type IN (:signInTypes)
       AND e.created_at >= a.started_at
       AND e.created_at <= a.started_at + INTERVAL '${LOGIN_ATTEMPT_WINDOW}'
       AND (a.next_started_at IS NULL OR e.created_at < a.next_started_at)
      GROUP BY a.user_id, a.started_at
    )
    SELECT ${PERCENTILES('completed_at - started_at')}
    FROM completed
    `,
    { ...window, signInTypes: [...SIGN_IN_SUCCESS_TYPES] },
  );

  return toIntervalStats(row);
}

/**
 * Of the accounts created in the window, how many hold a passkey, and how long the
 * first one took to arrive.
 *
 * Counted from `credentials` rows, not events. `registration_success` fires on
 * new-user registration, phone registration, magic link completion and passkey
 * enrollment alike, so it cannot tell an enrollment from anything else.
 */
async function passkeyAdoption(window: FunnelWindow) {
  const row = await selectOne<AdoptionRow>(
    `
    WITH cohort AS (
      SELECT id, created_at
      FROM users
      WHERE TRUE
        ${windowClause('created_at', window)}
    ),
    enrolled AS (
      SELECT c.created_at, MIN(cr."createdAt") AS enrolled_at
      FROM cohort c
      JOIN credentials cr ON cr."userId" = c.id
      GROUP BY c.id, c.created_at
    )
    SELECT (SELECT COUNT(*) FROM cohort) AS users,
           ${PERCENTILES('enrolled_at - created_at')}
    FROM enrolled
    `,
    { ...window },
  );

  const users = toNumber(row?.users) ?? 0;
  const timeToFirstPasskey = toIntervalStats(row);
  const withPasskey = timeToFirstPasskey.count;

  return {
    passkeyAdoption: {
      users,
      withPasskey,
      rate: users > 0 ? withPasskey / users : 0,
    },
    timeToFirstPasskey,
  };
}

export async function getFunnelMetrics(window: FunnelWindow = {}): Promise<FunnelMetrics> {
  const [registration, login, adoption] = await Promise.all([
    timeToRegistration(window),
    timeToLogin(window),
    passkeyAdoption(window),
  ]);

  return {
    timeToRegistration: registration,
    timeToLogin: login,
    ...adoption,
  };
}
