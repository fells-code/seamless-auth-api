import { MetadataService } from '@simplewebauthn/server';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { getSystemConfig } from '../../../src/config/getSystemConfig.js';
import { knownAuthenticatorName } from '../../../src/lib/knownAuthenticators.js';
import { getSequelize } from '../../../src/models/index.js';
import { Organization } from '../../../src/models/organizations.js';
import { SIGN_IN_SUCCESS_TYPES } from '../../../src/schemas/authEvent.types.js';
import {
  CoverageReportQuerySchema,
  resolveCoverageWindow,
} from '../../../src/schemas/coverageReport.js';
import {
  buildCoverageReport,
  coverageBuckets,
  coverageReportCsv,
  CoverageReportError,
  SIGN_IN_EVENT_TYPES,
} from '../../../src/services/coverageReport.js';
import { isMetadataServiceReady } from '../../../src/services/metadataServiceBootstrap.js';
import { buildSystemConfig } from '../../factories/systemConfigFactory.js';

vi.mock('../../../src/models/index.js', () => ({
  getSequelize: vi.fn(),
}));

vi.mock('@simplewebauthn/server', () => ({
  MetadataService: { getStatement: vi.fn() },
}));

vi.mock('../../../src/services/metadataServiceBootstrap.js', () => ({
  isMetadataServiceReady: vi.fn(),
}));

const query = vi.fn();
const orgId = '11111111-1111-4111-8111-111111111111';
const now = new Date('2026-10-06T12:00:00Z');

const authenticatorPolicy = {
  attachment: 'any',
  userVerification: 'required',
  attestation: 'direct',
  requireKnownAuthenticator: false,
  syncedPasskeys: 'block',
  aaguidAllowList: [],
  aaguidDenyList: ['aaaaaaaa-0000-0000-0000-000000000000'],
};

function sqlFor(fragment: string) {
  return query.mock.calls.find(([sql]) => String(sql).includes(fragment));
}

/** Routes each of the report's queries to a canned answer by a fragment unique to it. */
function answer(rows: {
  figures?: unknown[];
  organizations?: unknown[];
  mix?: unknown[];
  signIns?: unknown[];
}) {
  query.mockImplementation(async (sql: string) => {
    if (sql.includes('unnest(')) return rows.figures ?? [];
    if (sql.includes('FROM organizations o')) return rows.organizations ?? [];
    if (sql.includes('"backupEligible"')) return rows.mix ?? [];
    if (sql.includes('FROM auth_events')) return rows.signIns ?? [];
    throw new Error(`unexpected query: ${sql}`);
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  query.mockReset();
  vi.mocked(getSequelize).mockReturnValue({ query } as never);
  vi.mocked(getSystemConfig).mockResolvedValue(
    buildSystemConfig({
      login_methods: ['passkey', 'email_otp'],
      passkey_login_fallback_enabled: false,
      authenticator_policy: authenticatorPolicy,
    }) as never,
  );
  vi.mocked(isMetadataServiceReady).mockReturnValue(false);
});

describe('resolveCoverageWindow', () => {
  it('defaults to the 90 days ending today, both ends included', () => {
    const window = resolveCoverageWindow({}, now);

    expect(window.from).toBe('2026-07-09');
    expect(window.to).toBe('2026-10-06');
    expect(window.start.toISOString()).toBe('2026-07-09T00:00:00.000Z');
    expect(window.end.toISOString()).toBe('2026-10-07T00:00:00.000Z');
    expect((window.end.getTime() - window.start.getTime()) / 86_400_000).toBe(90);
  });

  it('runs a period given only `to` back 90 days from it', () => {
    expect(resolveCoverageWindow({ to: '2026-03-31' }, now).from).toBe('2026-01-01');
  });
});

describe('CoverageReportQuerySchema', () => {
  it('applies the defaults', () => {
    expect(CoverageReportQuerySchema.parse({})).toEqual({ bucket: 'month', format: 'json' });
  });

  it.each([
    [{ from: '2026-05-01', to: '2026-04-01' }, 'from must not be after to'],
    [{ from: '2010-01-01', to: '2026-01-01' }, 'at most 1827 days'],
  ])('rejects %j', (input, message) => {
    const result = CoverageReportQuerySchema.safeParse(input);

    expect(result.success).toBe(false);
    expect(result.error?.issues[0].message).toContain(message);
  });

  it.each([
    { from: '2026-02-30' },
    { to: '2026-04-01T00:00:00Z' },
    { bucket: 'day' },
    { format: 'xlsx' },
    { organizationId: 'nope' },
  ])('rejects %j', (input) => {
    expect(CoverageReportQuerySchema.safeParse(input).success).toBe(false);
  });

  it('accepts a single-day period', () => {
    expect(
      CoverageReportQuerySchema.safeParse({ from: '2026-04-01', to: '2026-04-01' }).success,
    ).toBe(true);
  });
});

describe('coverageBuckets', () => {
  const day = (date: Date) => date.toISOString().slice(0, 10);

  it('clips calendar months to the period', () => {
    const window = resolveCoverageWindow({ from: '2026-01-15', to: '2026-03-10' });

    expect(coverageBuckets(window, 'month').map((b) => [day(b.start), day(b.stop)])).toEqual([
      ['2026-01-15', '2026-02-01'],
      ['2026-02-01', '2026-03-01'],
      ['2026-03-01', '2026-03-11'],
    ]);
  });

  it('starts weeks on Monday', () => {
    // 2026-03-01 is a Sunday.
    const window = resolveCoverageWindow({ from: '2026-03-01', to: '2026-03-17' });

    expect(coverageBuckets(window, 'week').map((b) => [day(b.start), day(b.stop)])).toEqual([
      ['2026-03-01', '2026-03-02'],
      ['2026-03-02', '2026-03-09'],
      ['2026-03-09', '2026-03-16'],
      ['2026-03-16', '2026-03-18'],
    ]);
  });

  it('crosses a year boundary', () => {
    const window = resolveCoverageWindow({ from: '2025-12-20', to: '2026-01-05' });

    expect(coverageBuckets(window, 'month').map((b) => day(b.start))).toEqual([
      '2025-12-20',
      '2026-01-01',
    ]);
  });
});

describe('SIGN_IN_EVENT_TYPES', () => {
  it('covers exactly the sign-in success types the metrics count', () => {
    expect([...Object.values(SIGN_IN_EVENT_TYPES)].sort()).toEqual(
      [...SIGN_IN_SUCCESS_TYPES].sort(),
    );
  });
});

describe('knownAuthenticatorName', () => {
  it('matches case-insensitively and knows nothing of unlisted models', () => {
    expect(knownAuthenticatorName('EA9B8D66-4D01-1D21-3CE4-B6B48CB575D4')).toBe(
      'Google Password Manager',
    );
    expect(knownAuthenticatorName('ffffffff-0000-0000-0000-000000000000')).toBeNull();
    expect(knownAuthenticatorName(null)).toBeNull();
  });
});

describe('buildCoverageReport', () => {
  const query3Months = { from: '2026-01-01', to: '2026-03-31', bucket: 'month' as const };

  it('assembles policy, coverage, organizations, trend, authenticators and sign-ins', async () => {
    answer({
      figures: [
        { users: 10, passkeyUsers: 2 },
        { users: 12, passkeyUsers: 5 },
        { users: 12, passkeyUsers: 9 },
      ],
      organizations: [
        { organizationId: null, name: null, users: 2, passkeyUsers: 0 },
        { organizationId: 'org-b', name: 'Public Works', users: 6, passkeyUsers: 6 },
        { organizationId: 'org-a', name: 'Clerk', users: 4, passkeyUsers: 3 },
      ],
      mix: [
        {
          aaguid: 'fbfc3007-154e-4ecc-8c0b-6e020557d7bd',
          credentials: 7,
          users: 7,
          backupEligible: 7,
          backedUp: 6,
        },
        { aaguid: null, credentials: 2, users: 2, backupEligible: 0, backedUp: 0 },
      ],
      signIns: [
        { method: 'passkey', signIns: 30, users: 9 },
        { method: 'email_otp', signIns: 10, users: 3 },
      ],
    });

    const report = await buildCoverageReport(query3Months, now);

    expect(report.period).toEqual({ from: '2026-01-01', to: '2026-03-31' });
    expect(report.generatedAt).toBe('2026-10-06T12:00:00.000Z');
    expect(report.organizationId).toBeNull();
    expect(report.policy).toEqual({
      phishingResistantOnly: false,
      loginMethods: ['passkey', 'email_otp'],
      passkeyFallbackEnabled: false,
      authenticator: authenticatorPolicy,
    });
    expect(report.coverage).toEqual({ users: 12, passkeyUsers: 9, percent: 75 });
    expect(report.byOrganization.map((row) => [row.name, row.percent])).toEqual([
      ['Clerk', 75],
      ['Public Works', 100],
      [null, 0],
    ]);
    expect(report.trend).toEqual([
      { start: '2026-01-01', end: '2026-01-31', users: 10, passkeyUsers: 2, percent: 20 },
      { start: '2026-02-01', end: '2026-02-28', users: 12, passkeyUsers: 5, percent: 41.7 },
      { start: '2026-03-01', end: '2026-03-31', users: 12, passkeyUsers: 9, percent: 75 },
    ]);
    expect(report.authenticatorMix.map((row) => row.name)).toEqual(['iCloud Keychain', null]);
    expect(report.signInMix.total).toBe(40);
    expect(report.signInMix.phishingResistant).toBe(30);
    expect(report.signInMix.percent).toBe(75);
    expect(report.signInMix.methods.map((row) => row.method)).toEqual([
      'passkey',
      'email_otp',
      'phone_otp',
      'otp',
      'magic_link',
      'totp',
      'oauth',
    ]);
    expect(report.signInMix.methods.find((row) => row.method === 'totp')).toEqual({
      method: 'totp',
      phishingResistant: false,
      signIns: 0,
      users: 0,
    });

    const [, figuresOptions] = sqlFor('unnest(')!;
    expect(figuresOptions.replacements.stops.map((d: Date) => d.toISOString())).toEqual([
      '2026-02-01T00:00:00.000Z',
      '2026-03-01T00:00:00.000Z',
      '2026-04-01T00:00:00.000Z',
    ]);
    expect(String(sqlFor('unnest(')![0])).not.toContain('organization_memberships');

    const [signInSql, signInOptions] = sqlFor('FROM auth_events')!;
    expect(signInSql).toContain("e.metadata->>'channel' = 'email'");
    expect(signInOptions.replacements).toEqual(
      expect.objectContaining({
        start: new Date('2026-01-01T00:00:00Z'),
        end: new Date('2026-04-01T00:00:00Z'),
      }),
    );
  });

  it('states phishing-resistant-only as enforced passkey-only policy', async () => {
    vi.mocked(getSystemConfig).mockResolvedValue(
      buildSystemConfig({
        login_methods: ['passkey', 'email_otp', 'magic_link'],
        phishing_resistant_only: true,
        authenticator_policy: authenticatorPolicy,
      }) as never,
    );
    answer({});

    const report = await buildCoverageReport(query3Months, now);

    expect(report.policy).toEqual(
      expect.objectContaining({
        phishingResistantOnly: true,
        loginMethods: ['passkey'],
        passkeyFallbackEnabled: false,
      }),
    );
  });

  it('reports zeros, not NaN, for an empty deployment', async () => {
    answer({});

    const report = await buildCoverageReport(query3Months, now);

    expect(report.coverage).toEqual({ users: 0, passkeyUsers: 0, percent: 0 });
    expect(report.trend.every((row) => row.users === 0 && row.percent === 0)).toBe(true);
    expect(report.signInMix).toEqual(expect.objectContaining({ total: 0, percent: 0 }));
  });

  it('scopes every query to the organization', async () => {
    vi.mocked(Organization.findByPk).mockResolvedValue({ id: orgId } as never);
    answer({});

    const report = await buildCoverageReport({ ...query3Months, organizationId: orgId }, now);

    expect(report.organizationId).toBe(orgId);
    for (const fragment of ['unnest(', '"backupEligible"', 'FROM auth_events']) {
      const [sql, options] = sqlFor(fragment)!;
      expect(sql).toContain('m.organization_id = :organizationId');
      expect(options.replacements.organizationId).toBe(orgId);
    }
    expect(sqlFor('FROM auth_events')![0]).toContain('m.user_id = e.user_id');

    const [orgSql] = sqlFor('FROM organizations o')!;
    expect(orgSql).toContain('WHERE o.id = :organizationId');
    expect(orgSql).not.toContain('UNION ALL');
  });

  it('refuses an organization that does not exist', async () => {
    vi.mocked(Organization.findByPk).mockResolvedValue(null as never);

    await expect(
      buildCoverageReport({ ...query3Months, organizationId: orgId }, now),
    ).rejects.toEqual(new CoverageReportError(404, 'Organization not found'));
    expect(query).not.toHaveBeenCalled();
  });

  it('names an unlisted authenticator from the metadata service when it is up', async () => {
    vi.mocked(isMetadataServiceReady).mockReturnValue(true);
    vi.mocked(MetadataService.getStatement).mockImplementation(async (aaguid) => {
      if (aaguid === 'bbbbbbbb-0000-0000-0000-000000000000') {
        return { description: 'Security Key NFC' } as never;
      }
      throw new Error('not listed');
    });
    answer({
      mix: [
        {
          aaguid: 'bbbbbbbb-0000-0000-0000-000000000000',
          credentials: 1,
          users: 1,
          backupEligible: 0,
          backedUp: 0,
        },
        {
          aaguid: 'cccccccc-0000-0000-0000-000000000000',
          credentials: 1,
          users: 1,
          backupEligible: 0,
          backedUp: 0,
        },
      ],
    });

    const report = await buildCoverageReport(query3Months, now);

    expect(report.authenticatorMix.map((row) => row.name)).toEqual(['Security Key NFC', null]);
  });
});

describe('coverageReportCsv', () => {
  it('renders each section with its own header, escaped and guarded against formulas', async () => {
    answer({
      figures: [
        { users: 1, passkeyUsers: 0 },
        { users: 2, passkeyUsers: 1 },
        { users: 3, passkeyUsers: 2 },
      ],
      organizations: [
        { organizationId: 'org-a', name: 'Clerk, "Office"', users: 2, passkeyUsers: 1 },
        { organizationId: 'org-b', name: '=HYPERLINK("x")', users: 1, passkeyUsers: 1 },
        { organizationId: null, name: null, users: 0, passkeyUsers: 0 },
      ],
      mix: [{ aaguid: null, credentials: 2, users: 2, backupEligible: 1, backedUp: 1 }],
      signIns: [{ method: 'passkey', signIns: 4, users: 2 }],
    });

    const csv = coverageReportCsv(
      await buildCoverageReport({ ...query3Months(), bucket: 'month' }, now),
    );
    const lines = csv.split('\r\n');

    expect(csv.endsWith('\r\n')).toBe(true);
    expect(lines).toContain('Phishing-resistant only,false');
    expect(lines).toContain('Login methods,passkey email_otp');
    expect(lines).toContain('AAGUID deny list,aaaaaaaa-0000-0000-0000-000000000000');
    expect(lines).toContain('Organization,Organization ID,Active users,Passkey holders,Coverage %');
    expect(lines).toContain('All users,,3,2,66.7');
    expect(lines).toContain('"Clerk, ""Office""",org-a,2,1,50');
    expect(lines).toContain(`"'=HYPERLINK(""x"")",org-b,1,1,100`);
    expect(lines).toContain('No organization,,0,0,0');
    expect(lines).toContain('2026-01-01,2026-01-31,1,0,0');
    expect(lines).toContain('Not reported,,2,2,1,1');
    expect(lines).toContain('Passkey,true,4,2');
    expect(lines).toContain('Code (channel not recorded),false,0,0');
    expect(lines).toContain('Phishing-resistant share %,,100');

    // A blank line before every section title, so a pasted sheet keeps them apart.
    for (const title of [
      'Enforced policy',
      'Coverage by organization',
      'Coverage trend',
      'Authenticator mix',
      'Sign-in mix',
    ]) {
      expect(lines[lines.indexOf(title) - 1]).toBe('');
    }
  });

  function query3Months() {
    return { from: '2026-01-01', to: '2026-03-31' };
  }
});
