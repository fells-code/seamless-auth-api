import { QueryTypes } from 'sequelize';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { getSequelize } from '../../../src/models/index.js';
import { SIGN_IN_SUCCESS_TYPES } from '../../../src/schemas/authEvent.types.js';
import { getFunnelMetrics } from '../../../src/services/funnelMetrics.js';

vi.mock('../../../src/models/index.js', () => ({
  getSequelize: vi.fn(),
}));

const query = vi.fn();

type Call = { sql: string; options: { replacements: Record<string, unknown>; type: string } };

function calls(): Call[] {
  return query.mock.calls.map(([sql, options]) => ({ sql, options }));
}

function callFor(fragment: string): Call {
  const match = calls().find((call) => call.sql.includes(fragment));

  if (!match) throw new Error(`no query mentions ${fragment}`);

  return match;
}

// The driver hands back bigint counts as strings and percentiles as doubles.
function answerWith(rows: {
  registration?: Record<string, unknown>;
  login?: Record<string, unknown>;
  adoption?: Record<string, unknown>;
}) {
  query.mockImplementation(async (sql: string) => {
    if (sql.includes("type = 'user_created'")) return [rows.registration ?? {}];
    if (sql.includes("type = 'login_success'")) return [rows.login ?? {}];
    if (sql.includes('JOIN credentials')) return [rows.adoption ?? {}];

    throw new Error(`unexpected query: ${sql}`);
  });
}

beforeEach(() => {
  query.mockReset();
  vi.mocked(getSequelize).mockReturnValue({ query } as never);
});

describe('getFunnelMetrics', () => {
  it('runs one query per block and maps the driver rows into numbers', async () => {
    answerWith({
      registration: { count: '3', median_seconds: 90, p90_seconds: 258.0004 },
      login: { count: '2', median_seconds: 25, p90_seconds: 29 },
      adoption: { users: '5', count: '3', median_seconds: 86400.0043, p90_seconds: 86400 },
    });

    await expect(getFunnelMetrics()).resolves.toEqual({
      timeToRegistration: { count: 3, medianSeconds: 90, p90Seconds: 258 },
      timeToLogin: { count: 2, medianSeconds: 25, p90Seconds: 29 },
      passkeyAdoption: { users: 5, withPasskey: 3, rate: 0.6 },
      timeToFirstPasskey: { count: 3, medianSeconds: 86400.004, p90Seconds: 86400 },
    });

    expect(query).toHaveBeenCalledTimes(3);

    for (const call of calls()) {
      expect(call.options.type).toBe(QueryTypes.SELECT);
    }
  });

  it('reports empty blocks as zero counts with null percentiles, not NaN', async () => {
    answerWith({
      registration: { count: '0', median_seconds: null, p90_seconds: null },
      login: { count: '0', median_seconds: null, p90_seconds: null },
      adoption: { users: '0', count: '0', median_seconds: null, p90_seconds: null },
    });

    const empty = { count: 0, medianSeconds: null, p90Seconds: null };

    await expect(getFunnelMetrics()).resolves.toEqual({
      timeToRegistration: empty,
      timeToLogin: empty,
      passkeyAdoption: { users: 0, withPasskey: 0, rate: 0 },
      timeToFirstPasskey: empty,
    });
  });

  it('brackets attempts with the completed sign-in types, not every success event', async () => {
    answerWith({});

    await getFunnelMetrics();

    const login = callFor("type = 'login_success'");

    expect(login.options.replacements.signInTypes).toEqual([...SIGN_IN_SUCCESS_TYPES]);
    expect(login.sql).toContain('IN (:signInTypes)');
    // A retried attempt is attributed to the login_success it completed, and a sign-in
    // after the ephemeral token expired is not attributed at all.
    expect(login.sql).toContain('LEAD(created_at)');
    expect(login.sql).toContain("INTERVAL '5 minutes'");
  });

  it('applies the window to the cohort column of each query and nowhere else', async () => {
    answerWith({});

    const from = new Date('2026-09-01T00:00:00.000Z');
    const to = new Date('2026-09-08T00:00:00.000Z');

    await getFunnelMetrics({ from, to });

    for (const call of calls()) {
      expect(call.options.replacements).toMatchObject({ from, to });
      expect(call.sql).toContain('created_at >= :from');
      expect(call.sql).toContain('created_at <= :to');
    }

    // The join to the completing event is not windowed. A registration started on the
    // last day of the window and finished the next morning still counts.
    const registration = callFor("type = 'user_created'");
    const [, joined] = registration.sql.split('JOIN auth_events');

    expect(joined).not.toContain(':from');
    expect(joined).not.toContain(':to');
  });

  it('leaves a missing bound out of the SQL rather than binding undefined', async () => {
    answerWith({});

    await getFunnelMetrics({ from: new Date('2026-09-01T00:00:00.000Z') });

    for (const call of calls()) {
      expect(call.sql).toContain(':from');
      expect(call.sql).not.toContain(':to');
    }
  });

  it('counts passkeys from credentials rows, not registration events', async () => {
    answerWith({});

    await getFunnelMetrics();

    const adoption = callFor('JOIN credentials');

    expect(adoption.sql).toContain('cr."userId" = c.id');
    expect(adoption.sql).not.toContain('registration_success');
  });

  it('surfaces a query failure instead of answering with zeros', async () => {
    query.mockRejectedValue(new Error('relation "auth_events" does not exist'));

    await expect(getFunnelMetrics()).rejects.toThrow('auth_events');
  });
});
