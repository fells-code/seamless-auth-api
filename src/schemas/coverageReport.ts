/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { z } from 'zod';

export const COVERAGE_REPORT_DEFAULT_DAYS = 90;
export const COVERAGE_REPORT_MAX_DAYS = 1827;

const DAY_MS = 24 * 60 * 60 * 1000;

export interface CoverageWindow {
  from: string;
  to: string;
  /** Midnight UTC on `from`. */
  start: Date;
  /** Midnight UTC the day after `to`, so `to` is covered in full. */
  end: Date;
}

function isoDay(date: Date) {
  return date.toISOString().slice(0, 10);
}

/** Both dates are whole UTC days and both ends are included. */
export function resolveCoverageWindow(
  query: { from?: string; to?: string },
  now: Date = new Date(),
): CoverageWindow {
  const to = query.to ?? isoDay(now);
  const end = new Date(Date.parse(`${to}T00:00:00.000Z`) + DAY_MS);
  const from =
    query.from ?? isoDay(new Date(end.getTime() - COVERAGE_REPORT_DEFAULT_DAYS * DAY_MS));

  return { from, to, start: new Date(`${from}T00:00:00.000Z`), end };
}

const IsoDay = z.iso.date();

export const CoverageBucketSchema = z.enum(['week', 'month']);
export const CoverageFormatSchema = z.enum(['json', 'csv']);

export const CoverageReportQuerySchema = z
  .object({
    from: IsoDay.optional(),
    to: IsoDay.optional(),
    organizationId: z.uuid().optional(),
    bucket: CoverageBucketSchema.default('month'),
    format: CoverageFormatSchema.default('json'),
  })
  .superRefine((query, ctx) => {
    // Zod still runs this when a date failed its own format check, which it has reported.
    if ([query.from, query.to].some((day) => day !== undefined && !IsoDay.safeParse(day).success)) {
      return;
    }

    const { start, end } = resolveCoverageWindow(query);
    const days = Math.round((end.getTime() - start.getTime()) / DAY_MS);

    if (days < 1) {
      ctx.addIssue({ code: 'custom', path: ['from'], message: 'from must not be after to' });
    } else if (days > COVERAGE_REPORT_MAX_DAYS) {
      ctx.addIssue({
        code: 'custom',
        path: ['from'],
        message: `The period may cover at most ${COVERAGE_REPORT_MAX_DAYS} days`,
      });
    }
  });

export type CoverageReportQuery = z.infer<typeof CoverageReportQuerySchema>;

const CoverageFiguresSchema = z.object({
  users: z.number().int(),
  passkeyUsers: z.number().int(),
  /** `passkeyUsers` over `users`, as a percentage to one decimal place. */
  percent: z.number(),
});

export const SIGN_IN_MIX_METHODS = [
  'passkey',
  'email_otp',
  'phone_otp',
  'otp',
  'magic_link',
  'totp',
  'oauth',
] as const;

export const CoverageReportResponseSchema = z.object({
  period: z.object({ from: z.iso.date(), to: z.iso.date() }),
  generatedAt: z.iso.datetime(),
  organizationId: z.uuid().nullable(),
  bucket: CoverageBucketSchema,
  policy: z.object({
    phishingResistantOnly: z.boolean(),
    loginMethods: z.array(z.string()),
    passkeyFallbackEnabled: z.boolean(),
    authenticator: z.object({
      attestation: z.string(),
      userVerification: z.string(),
      attachment: z.string(),
      syncedPasskeys: z.string(),
      requireKnownAuthenticator: z.boolean(),
      aaguidAllowList: z.array(z.string()),
      aaguidDenyList: z.array(z.string()),
    }),
  }),
  coverage: CoverageFiguresSchema,
  byOrganization: z.array(
    CoverageFiguresSchema.extend({
      organizationId: z.string().nullable(),
      name: z.string().nullable(),
    }),
  ),
  trend: z.array(
    CoverageFiguresSchema.extend({
      start: z.iso.date(),
      end: z.iso.date(),
    }),
  ),
  authenticatorMix: z.array(
    z.object({
      aaguid: z.string().nullable(),
      name: z.string().nullable(),
      credentials: z.number().int(),
      users: z.number().int(),
      backupEligible: z.number().int(),
      backedUp: z.number().int(),
    }),
  ),
  signInMix: z.object({
    total: z.number().int(),
    phishingResistant: z.number().int(),
    percent: z.number(),
    methods: z.array(
      z.object({
        method: z.enum(SIGN_IN_MIX_METHODS),
        phishingResistant: z.boolean(),
        signIns: z.number().int(),
        users: z.number().int(),
      }),
    ),
  }),
});

export type CoverageReport = z.infer<typeof CoverageReportResponseSchema>;
