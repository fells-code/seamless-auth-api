/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { QueryTypes } from 'sequelize';

import { getSequelize } from '../models/index.js';
import {
  AuthEventType,
  SIGN_IN_FAILURE_TYPES,
  SIGN_IN_SUCCESS_TYPES,
} from '../schemas/authEvent.types.js';
import type { FunnelWindow } from './funnelMetrics.js';

export const SIGN_IN_METHODS = ['passkey', 'otp', 'magic_link', 'oauth', 'totp'] as const;

export type SignInMethod = (typeof SIGN_IN_METHODS)[number];

/** The event-type prefix each method's sign-in outcomes are named under. */
const METHOD_PREFIX: Record<SignInMethod, string> = {
  passkey: 'webauthn_login',
  otp: 'verify_otp',
  magic_link: 'magic_link',
  oauth: 'oauth_login',
  totp: 'totp',
};

const SIGN_IN_TYPES: readonly AuthEventType[] = [
  ...SIGN_IN_SUCCESS_TYPES,
  ...SIGN_IN_FAILURE_TYPES,
];

/** A code or link went out. Passkeys have no such step. */
const DELIVERY_TYPES: readonly AuthEventType[] = ['otp_success', 'magic_link_requested'];

/** The row that starts an attempt, and so mints the token every later step carries. */
const START_TYPES: readonly AuthEventType[] = ['login_success', 'user_created'];

export interface SignInBreakdownRow {
  method: SignInMethod;
  deviceClass: string | null;
  mailProvider: string | null;
  owner: boolean | null;
  success: number;
  failed: number;
}

export interface SignInAttempts {
  started: number;
  delivered: number;
  presented: number;
  completed: number;
}

export interface SignInMetrics {
  deploymentId: string | null;
  attempts: SignInAttempts;
  signIns: { success: number; failed: number; successRate: number };
  breakdown: SignInBreakdownRow[];
}

type BreakdownRow = {
  method: SignInMethod;
  device_class: string | null;
  mail_provider: string | null;
  owner: boolean | null;
  success: string | number;
  failed: string | number;
};

type AttemptsRow = {
  started: string | number;
  delivered: string | number;
  presented: string | number;
  completed: string | number;
};

function count(value: string | number | null | undefined): number {
  const parsed = Number(value);

  return Number.isFinite(parsed) ? parsed : 0;
}

function windowClause(window: FunnelWindow) {
  const clauses: string[] = [];

  if (window.from) clauses.push('created_at >= :from');
  if (window.to) clauses.push('created_at <= :to');

  return clauses.length ? `AND ${clauses.join(' AND ')}` : '';
}

function methodCase() {
  return SIGN_IN_METHODS.map((method) => `WHEN type IN (:${method}Types) THEN '${method}'`).join(
    '\n           ',
  );
}

function methodTypeReplacements() {
  return Object.fromEntries(
    SIGN_IN_METHODS.map((method) => [
      `${method}Types`,
      SIGN_IN_TYPES.filter((type) => type.startsWith(METHOD_PREFIX[method])),
    ]),
  );
}

/**
 * Sign-in outcomes per method, device class, mail provider and owner flag.
 *
 * The unit is a method presented within an attempt, not an event. A completed OTP
 * sign-in writes `verify_otp_success` twice, and a person who mistypes a code and
 * then gets it right has failed nothing, so events are folded by attempt and method
 * first: an attempt counts as a success for a method if any of that method's success
 * events carry its id. A row with no attempt id (written before the claim existed, or
 * from a magic link opened on another device) stands as its own attempt, so older
 * rows still count once each.
 */
async function breakdown(window: FunnelWindow): Promise<SignInBreakdownRow[]> {
  const rows = await getSequelize().query<BreakdownRow>(
    `
    WITH presented AS (
      SELECT COALESCE(attempt_id::text, id::text) AS attempt,
             CASE
           ${methodCase()}
             END AS method,
             device_class,
             mail_provider,
             owner,
             BOOL_OR(type IN (:successTypes)) AS succeeded
      FROM auth_events
      WHERE type IN (:signInTypes)
        ${windowClause(window)}
      GROUP BY 1, 2, 3, 4, 5
    )
    SELECT method,
           device_class,
           mail_provider,
           owner,
           COUNT(*) FILTER (WHERE succeeded) AS success,
           COUNT(*) FILTER (WHERE NOT succeeded) AS failed
    FROM presented
    GROUP BY 1, 2, 3, 4
    ORDER BY 1, 2, 3, 4
    `,
    {
      replacements: {
        ...window,
        signInTypes: [...SIGN_IN_TYPES],
        successTypes: [...SIGN_IN_SUCCESS_TYPES],
        ...methodTypeReplacements(),
      },
      type: QueryTypes.SELECT,
    },
  );

  return rows.map((row) => ({
    method: row.method,
    deviceClass: row.device_class,
    mailProvider: row.mail_provider,
    owner: row.owner,
    success: count(row.success),
    failed: count(row.failed),
  }));
}

/**
 * Where attempts stop. Only attempts that carry an id are counted, which is every
 * one started since the claim was added, so the four numbers are comparable.
 *
 * `delivered` is not a strict step: a passkey attempt goes from started to presented
 * with nothing sent. Read `started - presented` as "gave up before proving anything"
 * and `delivered - presented` as "was sent a code or link and never came back".
 */
async function attempts(window: FunnelWindow): Promise<SignInAttempts> {
  const [row] = await getSequelize().query<AttemptsRow>(
    `
    SELECT COUNT(DISTINCT attempt_id) FILTER (WHERE type IN (:startTypes)) AS started,
           COUNT(DISTINCT attempt_id) FILTER (WHERE type IN (:deliveryTypes)) AS delivered,
           COUNT(DISTINCT attempt_id) FILTER (WHERE type IN (:signInTypes)) AS presented,
           COUNT(DISTINCT attempt_id) FILTER (WHERE type IN (:successTypes)) AS completed
    FROM auth_events
    WHERE attempt_id IS NOT NULL
      ${windowClause(window)}
    `,
    {
      replacements: {
        ...window,
        startTypes: [...START_TYPES],
        deliveryTypes: [...DELIVERY_TYPES],
        signInTypes: [...SIGN_IN_TYPES],
        successTypes: [...SIGN_IN_SUCCESS_TYPES],
      },
      type: QueryTypes.SELECT,
    },
  );

  return {
    started: count(row?.started),
    delivered: count(row?.delivered),
    presented: count(row?.presented),
    completed: count(row?.completed),
  };
}

export async function getSignInMetrics(window: FunnelWindow = {}): Promise<SignInMetrics> {
  const [rows, steps] = await Promise.all([breakdown(window), attempts(window)]);

  const success = rows.reduce((total, row) => total + row.success, 0);
  const failed = rows.reduce((total, row) => total + row.failed, 0);

  return {
    deploymentId: process.env.APP_ID?.trim() || null,
    attempts: steps,
    signIns: {
      success,
      failed,
      successRate: success + failed > 0 ? success / (success + failed) : 0,
    },
    breakdown: rows,
  };
}
