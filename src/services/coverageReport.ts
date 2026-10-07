/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { MetadataService } from '@simplewebauthn/server';
import { QueryTypes } from 'sequelize';

import { getSystemConfig } from '../config/getSystemConfig.js';
import { ANONYMOUS_AAGUID, knownAuthenticatorName } from '../lib/knownAuthenticators.js';
import { getSequelize } from '../models/index.js';
import { Organization } from '../models/organizations.js';
import type { AuthEventType } from '../schemas/authEvent.types.js';
import {
  type CoverageReport,
  type CoverageReportQuery,
  type CoverageWindow,
  resolveCoverageWindow,
  SIGN_IN_MIX_METHODS,
} from '../schemas/coverageReport.js';
import { getLoginPolicy } from './loginPolicyService.js';
import { isMetadataServiceReady } from './metadataServiceBootstrap.js';

const DAY_MS = 24 * 60 * 60 * 1000;

type SignInMixMethod = (typeof SIGN_IN_MIX_METHODS)[number];

/** The success event each method writes when a sign-in completes. */
export const SIGN_IN_EVENT_TYPES = {
  passkey: 'webauthn_login_success',
  otp: 'verify_otp_success',
  magic_link: 'magic_link_poll_completed_successfully',
  totp: 'totp_success',
  oauth: 'oauth_login_success',
} as const satisfies Record<string, AuthEventType>;

export class CoverageReportError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = 'CoverageReportError';
  }
}

interface Bucket {
  start: Date;
  stop: Date;
}

interface Figures {
  users: number;
  passkeyUsers: number;
}

function isoDay(date: Date) {
  return date.toISOString().slice(0, 10);
}

function percent(part: number, whole: number) {
  return whole > 0 ? Math.round((part / whole) * 1000) / 10 : 0;
}

function withPercent<T extends Figures>(figures: T) {
  return { ...figures, percent: percent(figures.passkeyUsers, figures.users) };
}

/**
 * Calendar buckets in UTC. The first and last are clipped to the period, so a bucket can be
 * shorter than a week or a month. Weeks start on Monday.
 */
export function coverageBuckets(window: CoverageWindow, bucket: 'week' | 'month'): Bucket[] {
  const buckets: Bucket[] = [];
  let cursor = window.start;

  while (cursor < window.end) {
    const next =
      bucket === 'month'
        ? new Date(Date.UTC(cursor.getUTCFullYear(), cursor.getUTCMonth() + 1, 1))
        : new Date(cursor.getTime() + ((8 - cursor.getUTCDay()) % 7 || 7) * DAY_MS);
    const stop = next < window.end ? next : window.end;

    buckets.push({ start: cursor, stop });
    cursor = stop;
  }

  return buckets;
}

function organizationClause(organizationId: string | undefined, userColumn = 'u.id') {
  return organizationId
    ? `AND EXISTS (
         SELECT 1 FROM organization_memberships m
         WHERE m.user_id = ${userColumn} AND m.organization_id = :organizationId
       )`
    : '';
}

/**
 * Active users, and those of them holding a passkey, as of each instant. A user counts from
 * `created_at` and a passkey holder from their earliest surviving credential.
 */
async function figuresAsOf(stops: Date[], end: Date, organizationId?: string): Promise<Figures[]> {
  const rows = await getSequelize().query<Figures>(
    `
    WITH scoped AS (
      SELECT u.created_at,
             (SELECT MIN(c."createdAt") FROM credentials c WHERE c."userId" = u.id) AS first_passkey_at
      FROM users u
      WHERE u.revoked = false
        AND u.created_at < :end
        ${organizationClause(organizationId)}
    )
    SELECT b.stop,
           (COUNT(s.created_at) FILTER (WHERE s.created_at < b.stop))::int AS users,
           (COUNT(s.created_at) FILTER (WHERE s.first_passkey_at < b.stop))::int AS "passkeyUsers"
    FROM unnest(ARRAY[:stops]::timestamptz[]) AS b(stop)
    LEFT JOIN scoped s ON true
    GROUP BY b.stop
    ORDER BY b.stop
    `,
    {
      replacements: { stops, end, organizationId: organizationId ?? null },
      type: QueryTypes.SELECT,
    },
  );

  return stops.map((_, index) => ({
    users: rows[index]?.users ?? 0,
    passkeyUsers: rows[index]?.passkeyUsers ?? 0,
  }));
}

async function figuresByOrganization(end: Date, organizationId?: string) {
  const rows = await getSequelize().query<
    Figures & { organizationId: string | null; name: string | null }
  >(
    `
    WITH scoped AS (
      SELECT u.id,
             EXISTS (
               SELECT 1 FROM credentials c WHERE c."userId" = u.id AND c."createdAt" < :end
             ) AS has_passkey
      FROM users u
      WHERE u.revoked = false AND u.created_at < :end
    )
    SELECT o.id AS "organizationId",
           o.name,
           COUNT(s.id)::int AS users,
           (COUNT(s.id) FILTER (WHERE s.has_passkey))::int AS "passkeyUsers"
    FROM organizations o
    LEFT JOIN organization_memberships m ON m.organization_id = o.id
    LEFT JOIN scoped s ON s.id = m.user_id
    ${organizationId ? 'WHERE o.id = :organizationId' : ''}
    GROUP BY o.id, o.name
    ${
      organizationId
        ? ''
        : `UNION ALL
    SELECT NULL, NULL, COUNT(*)::int, (COUNT(*) FILTER (WHERE s.has_passkey))::int
    FROM scoped s
    WHERE NOT EXISTS (SELECT 1 FROM organization_memberships m WHERE m.user_id = s.id)`
    }
    `,
    {
      replacements: { end, organizationId: organizationId ?? null },
      type: QueryTypes.SELECT,
    },
  );

  // Named organizations first, alphabetically, and the users in none of them last.
  return [...rows]
    .sort((a, b) => {
      if (a.organizationId === null) return 1;
      if (b.organizationId === null) return -1;
      return (
        (a.name ?? '').localeCompare(b.name ?? '') ||
        a.organizationId.localeCompare(b.organizationId)
      );
    })
    .map((row) => withPercent(row));
}

async function metadataName(aaguid: string) {
  if (!isMetadataServiceReady()) return null;

  try {
    return (await MetadataService.getStatement(aaguid))?.description ?? null;
  } catch {
    return null;
  }
}

async function authenticatorMix(end: Date, organizationId?: string) {
  const rows = await getSequelize().query<{
    aaguid: string | null;
    credentials: number;
    users: number;
    backupEligible: number;
    backedUp: number;
  }>(
    `
    SELECT CASE
             WHEN NULLIF(TRIM(c.aaguid), '') IS NULL OR c.aaguid = :anonymous THEN NULL
             ELSE LOWER(TRIM(c.aaguid))
           END AS aaguid,
           COUNT(*)::int AS credentials,
           COUNT(DISTINCT c."userId")::int AS users,
           (COUNT(*) FILTER (WHERE c."deviceType" = 'multiDevice'))::int AS "backupEligible",
           (COUNT(*) FILTER (WHERE c.backedup))::int AS "backedUp"
    FROM credentials c
    JOIN users u ON u.id = c."userId"
    WHERE u.revoked = false
      AND c."createdAt" < :end
      ${organizationClause(organizationId)}
    GROUP BY 1
    ORDER BY 2 DESC, 1 ASC NULLS LAST
    `,
    {
      replacements: { end, anonymous: ANONYMOUS_AAGUID, organizationId: organizationId ?? null },
      type: QueryTypes.SELECT,
    },
  );

  return Promise.all(
    rows.map(async (row) => ({
      ...row,
      name: row.aaguid
        ? (knownAuthenticatorName(row.aaguid) ?? (await metadataName(row.aaguid)))
        : null,
    })),
  );
}

/**
 * Completed sign-ins in the period, folded by attempt the way the sign-in metrics are, so an
 * OTP sign-in that writes `verify_otp_success` twice counts once. A code verification is
 * split by the channel it recorded; rows written before the channel was recorded stay `otp`.
 */
async function signInMix(window: CoverageWindow, organizationId?: string) {
  const rows = await getSequelize().query<{
    method: SignInMixMethod;
    signIns: number;
    users: number;
  }>(
    `
    WITH completed AS (
      SELECT COALESCE(e.attempt_id::text, e.id::text) AS attempt,
             e.user_id,
             CASE
               WHEN e.type = :passkeyType THEN 'passkey'
               WHEN e.type = :otpType AND e.metadata->>'channel' = 'email' THEN 'email_otp'
               WHEN e.type = :otpType AND e.metadata->>'channel' = 'sms' THEN 'phone_otp'
               WHEN e.type = :otpType THEN 'otp'
               WHEN e.type = :magicLinkType THEN 'magic_link'
               WHEN e.type = :totpType THEN 'totp'
               WHEN e.type = :oauthType THEN 'oauth'
             END AS method
      FROM auth_events e
      WHERE e.type IN (:types)
        AND e.created_at >= :start
        AND e.created_at < :end
        ${organizationClause(organizationId, 'e.user_id')}
    )
    SELECT method,
           COUNT(DISTINCT attempt)::int AS "signIns",
           COUNT(DISTINCT user_id)::int AS users
    FROM completed
    GROUP BY method
    `,
    {
      replacements: {
        start: window.start,
        end: window.end,
        organizationId: organizationId ?? null,
        types: Object.values(SIGN_IN_EVENT_TYPES),
        passkeyType: SIGN_IN_EVENT_TYPES.passkey,
        otpType: SIGN_IN_EVENT_TYPES.otp,
        magicLinkType: SIGN_IN_EVENT_TYPES.magic_link,
        totpType: SIGN_IN_EVENT_TYPES.totp,
        oauthType: SIGN_IN_EVENT_TYPES.oauth,
      },
      type: QueryTypes.SELECT,
    },
  );

  const byMethod = new Map(rows.map((row) => [row.method, row]));
  const methods = SIGN_IN_MIX_METHODS.map((method) => ({
    method,
    phishingResistant: method === 'passkey',
    signIns: byMethod.get(method)?.signIns ?? 0,
    users: byMethod.get(method)?.users ?? 0,
  }));
  const total = methods.reduce((sum, row) => sum + row.signIns, 0);
  const phishingResistant = methods
    .filter((row) => row.phishingResistant)
    .reduce((sum, row) => sum + row.signIns, 0);

  return { total, phishingResistant, percent: percent(phishingResistant, total), methods };
}

async function enforcedPolicy() {
  const [login, config] = await Promise.all([getLoginPolicy(), getSystemConfig()]);
  const authenticator = config.authenticator_policy;

  return {
    phishingResistantOnly: login.phishingResistantOnly,
    loginMethods: [...login.loginMethods],
    passkeyFallbackEnabled: login.passkeyFallbackEnabled,
    authenticator: {
      attestation: authenticator.attestation,
      userVerification: authenticator.userVerification,
      attachment: authenticator.attachment,
      syncedPasskeys: authenticator.syncedPasskeys,
      requireKnownAuthenticator: authenticator.requireKnownAuthenticator,
      aaguidAllowList: [...authenticator.aaguidAllowList],
      aaguidDenyList: [...authenticator.aaguidDenyList],
    },
  };
}

export async function buildCoverageReport(
  query: Pick<CoverageReportQuery, 'from' | 'to' | 'organizationId' | 'bucket'>,
  now: Date = new Date(),
): Promise<CoverageReport> {
  const { organizationId, bucket } = query;

  if (organizationId && !(await Organization.findByPk(organizationId))) {
    throw new CoverageReportError(404, 'Organization not found');
  }

  const window = resolveCoverageWindow(query, now);
  const buckets = coverageBuckets(window, bucket);

  const [policy, figures, byOrganization, mix, signIns] = await Promise.all([
    enforcedPolicy(),
    figuresAsOf(
      buckets.map((entry) => entry.stop),
      window.end,
      organizationId,
    ),
    figuresByOrganization(window.end, organizationId),
    authenticatorMix(window.end, organizationId),
    signInMix(window, organizationId),
  ]);

  return {
    period: { from: window.from, to: window.to },
    generatedAt: now.toISOString(),
    organizationId: organizationId ?? null,
    bucket,
    policy,
    // The last bucket closes at the end of the period, so it is the coverage as of `to`.
    coverage: withPercent(figures[figures.length - 1] ?? { users: 0, passkeyUsers: 0 }),
    byOrganization,
    trend: buckets.map((entry, index) => ({
      start: isoDay(entry.start),
      end: isoDay(new Date(entry.stop.getTime() - DAY_MS)),
      ...withPercent(figures[index]),
    })),
    authenticatorMix: mix,
    signInMix: signIns,
  };
}

/** Spreadsheet formula injection: a cell starting with one of these is evaluated on paste. */
const FORMULA_PREFIX = /^[=+\-@\t\r]/;

function csvCell(value: string | number | boolean | null) {
  if (value === null) return '';
  if (typeof value !== 'string') return String(value);

  const text = FORMULA_PREFIX.test(value) ? `'${value}` : value;

  return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

function csvRow(...cells: Array<string | number | boolean | null>) {
  return cells.map(csvCell).join(',');
}

const METHOD_LABELS: Record<SignInMixMethod, string> = {
  passkey: 'Passkey',
  email_otp: 'Email code',
  phone_otp: 'Phone code',
  otp: 'Code (channel not recorded)',
  magic_link: 'Magic link',
  totp: 'Authenticator app (TOTP)',
  oauth: 'OAuth',
};

/** Sections are separated by a blank line and each carries its own header row. */
export function coverageReportCsv(report: CoverageReport) {
  const { policy } = report;
  const lines = [
    csvRow('Authentication coverage report'),
    csvRow('Period from', report.period.from),
    csvRow('Period to', report.period.to),
    csvRow('Organization ID', report.organizationId),
    csvRow('Generated at', report.generatedAt),
    '',
    csvRow('Enforced policy'),
    csvRow('Setting', 'Value'),
    csvRow('Phishing-resistant only', policy.phishingResistantOnly),
    csvRow('Login methods', policy.loginMethods.join(' ')),
    csvRow('Passkey fallback enabled', policy.passkeyFallbackEnabled),
    csvRow('Attestation', policy.authenticator.attestation),
    csvRow('User verification', policy.authenticator.userVerification),
    csvRow('Authenticator attachment', policy.authenticator.attachment),
    csvRow('Synced passkeys', policy.authenticator.syncedPasskeys),
    csvRow('Require known authenticator', policy.authenticator.requireKnownAuthenticator),
    csvRow('AAGUID allow list', policy.authenticator.aaguidAllowList.join(' ')),
    csvRow('AAGUID deny list', policy.authenticator.aaguidDenyList.join(' ')),
    '',
    csvRow('Coverage by organization'),
    csvRow('Organization', 'Organization ID', 'Active users', 'Passkey holders', 'Coverage %'),
    csvRow(
      'All users',
      null,
      report.coverage.users,
      report.coverage.passkeyUsers,
      report.coverage.percent,
    ),
    ...report.byOrganization.map((row) =>
      csvRow(
        row.organizationId === null ? 'No organization' : (row.name ?? ''),
        row.organizationId,
        row.users,
        row.passkeyUsers,
        row.percent,
      ),
    ),
    '',
    csvRow('Coverage trend'),
    csvRow('Period start', 'Period end', 'Active users', 'Passkey holders', 'Coverage %'),
    ...report.trend.map((row) =>
      csvRow(row.start, row.end, row.users, row.passkeyUsers, row.percent),
    ),
    '',
    csvRow('Authenticator mix'),
    csvRow('AAGUID', 'Authenticator', 'Credentials', 'Users', 'Backup eligible', 'Backed up'),
    ...report.authenticatorMix.map((row) =>
      csvRow(
        row.aaguid ?? 'Not reported',
        row.name,
        row.credentials,
        row.users,
        row.backupEligible,
        row.backedUp,
      ),
    ),
    '',
    csvRow('Sign-in mix'),
    csvRow('Method', 'Phishing resistant', 'Sign-ins', 'Users'),
    ...report.signInMix.methods.map((row) =>
      csvRow(METHOD_LABELS[row.method], row.phishingResistant, row.signIns, row.users),
    ),
    csvRow('All methods', null, report.signInMix.total, null),
    csvRow('Phishing-resistant share %', null, report.signInMix.percent),
  ];

  return `${lines.join('\r\n')}\r\n`;
}
