import { beforeEach, describe, expect, it, vi } from 'vitest';

import { getSequelize } from '../../../src/models/index.js';
import { getReviewAccounts } from '../../../src/services/reviewAccountUsage.js';

vi.mock('../../../src/models/index.js', () => ({
  getSequelize: vi.fn(),
}));

const query = vi.fn();
const now = new Date('2026-10-06T12:00:00.000Z');

beforeEach(() => {
  query.mockReset();
  vi.mocked(getSequelize).mockReturnValue({ query } as never);
  vi.stubEnv('REVIEW_ACCOUNT_EMAILS', 'review@example.com');
  vi.stubEnv('REVIEW_ACCOUNT_CODE', 'REVUEW');
});

describe('getReviewAccounts', () => {
  it('reads flagged code events in the window and never returns the code', async () => {
    query.mockResolvedValue([
      { signIns: 3, failedVerifications: 1, lastSignInAt: new Date('2026-10-05T09:30:00.000Z') },
    ]);

    const result = await getReviewAccounts({ days: 30 }, now);

    expect(result).toEqual({
      enabled: true,
      emails: ['review@example.com'],
      codeConfigured: true,
      recentSignIns: {
        days: 30,
        count: 3,
        failedVerifications: 1,
        lastSignInAt: '2026-10-05T09:30:00.000Z',
      },
    });
    expect(JSON.stringify(result)).not.toContain('REVUEW');

    const [sql, options] = query.mock.calls[0];
    expect(sql).toContain('metadata ->> :flagKey');
    expect(options.replacements).toEqual({
      successType: 'verify_otp_success',
      failedType: 'verify_otp_failed',
      since: new Date('2026-09-06T12:00:00.000Z'),
      flagKey: 'reviewAccount',
    });
  });

  it('reads counts the driver returns as strings', async () => {
    query.mockResolvedValue([
      { signIns: '2', failedVerifications: '0', lastSignInAt: '2026-10-01T00:00:00Z' },
    ]);

    const { recentSignIns } = await getReviewAccounts({ days: 7 }, now);

    expect(recentSignIns).toEqual({
      days: 7,
      count: 2,
      failedVerifications: 0,
      lastSignInAt: '2026-10-01T00:00:00.000Z',
    });
  });

  it('reports no use when nothing matched', async () => {
    query.mockResolvedValue([{ signIns: 0, failedVerifications: 0, lastSignInAt: null }]);

    const { recentSignIns } = await getReviewAccounts({ days: 30 }, now);

    expect(recentSignIns).toEqual({
      days: 30,
      count: 0,
      failedVerifications: 0,
      lastSignInAt: null,
    });
  });

  it('treats an empty result as no use', async () => {
    query.mockResolvedValue([]);

    const { recentSignIns } = await getReviewAccounts({ days: 30 });

    expect(recentSignIns).toEqual({
      days: 30,
      count: 0,
      failedVerifications: 0,
      lastSignInAt: null,
    });
  });

  it('still reports past use once review accounts are switched off', async () => {
    vi.stubEnv('REVIEW_ACCOUNT_EMAILS', '');
    vi.stubEnv('REVIEW_ACCOUNT_CODE', '');
    query.mockResolvedValue([
      { signIns: 1, failedVerifications: 0, lastSignInAt: '2026-09-20T00:00:00.000Z' },
    ]);

    const result = await getReviewAccounts({ days: 30 }, now);

    expect(result).toMatchObject({ enabled: false, emails: [], codeConfigured: false });
    expect(result.recentSignIns.count).toBe(1);
  });
});
