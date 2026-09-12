import { QueryTypes } from 'sequelize';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { getSequelize } from '../../../src/models/index.js';
import {
  SIGN_IN_FAILURE_TYPES,
  SIGN_IN_SUCCESS_TYPES,
} from '../../../src/schemas/authEvent.types.js';
import { getSignInMetrics } from '../../../src/services/signInMetrics.js';

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

// The driver hands back bigint counts as strings.
function answerWith(rows: {
  breakdown?: Record<string, unknown>[];
  attempts?: Record<string, unknown>;
}) {
  query.mockImplementation(async (sql: string) => {
    if (sql.includes('WITH presented')) return rows.breakdown ?? [];
    if (sql.includes('COUNT(DISTINCT attempt_id)')) return [rows.attempts ?? {}];

    throw new Error(`unexpected query: ${sql}`);
  });
}

beforeEach(() => {
  query.mockReset();
  vi.mocked(getSequelize).mockReturnValue({ query } as never);
});

afterEach(() => {
  vi.unstubAllEnvs();
});

describe('getSignInMetrics', () => {
  it('maps the driver rows into the response and totals the breakdown', async () => {
    vi.stubEnv('APP_ID', 'gen-42');
    answerWith({
      breakdown: [
        {
          method: 'passkey',
          device_class: 'ios',
          mail_provider: 'gmail',
          owner: false,
          success: '40',
          failed: '2',
        },
        {
          method: 'magic_link',
          device_class: 'windows',
          mail_provider: 'other',
          owner: true,
          success: '3',
          failed: '0',
        },
        {
          method: 'otp',
          device_class: null,
          mail_provider: null,
          owner: null,
          success: '5',
          failed: '5',
        },
      ],
      attempts: { started: '60', delivered: '20', presented: '55', completed: '48' },
    });

    await expect(getSignInMetrics()).resolves.toEqual({
      deploymentId: 'gen-42',
      attempts: { started: 60, delivered: 20, presented: 55, completed: 48 },
      signIns: { success: 48, failed: 7, successRate: 48 / 55 },
      breakdown: [
        {
          method: 'passkey',
          deviceClass: 'ios',
          mailProvider: 'gmail',
          owner: false,
          success: 40,
          failed: 2,
        },
        {
          method: 'magic_link',
          deviceClass: 'windows',
          mailProvider: 'other',
          owner: true,
          success: 3,
          failed: 0,
        },
        {
          method: 'otp',
          deviceClass: null,
          mailProvider: null,
          owner: null,
          success: 5,
          failed: 5,
        },
      ],
    });

    expect(query).toHaveBeenCalledTimes(2);

    for (const call of calls()) {
      expect(call.options.type).toBe(QueryTypes.SELECT);
    }
  });

  it('answers an empty deployment with zeros, no NaN, and a null deployment id', async () => {
    vi.stubEnv('APP_ID', '');
    answerWith({ attempts: { started: '0', delivered: '0', presented: '0', completed: '0' } });

    await expect(getSignInMetrics()).resolves.toEqual({
      deploymentId: null,
      attempts: { started: 0, delivered: 0, presented: 0, completed: 0 },
      signIns: { success: 0, failed: 0, successRate: 0 },
      breakdown: [],
    });
  });

  it('folds events by attempt and method before counting, so a double-logged success is one', async () => {
    answerWith({});

    await getSignInMetrics();

    const breakdown = callFor('WITH presented');

    // One row per attempt and method, with the attempt falling back to the row id.
    expect(breakdown.sql).toContain('COALESCE(attempt_id::text, id::text) AS attempt');
    expect(breakdown.sql).toContain('BOOL_OR(type IN (:successTypes)) AS succeeded');
    expect(breakdown.sql).toContain('COUNT(*) FILTER (WHERE succeeded) AS success');
    expect(breakdown.sql).toContain('COUNT(*) FILTER (WHERE NOT succeeded) AS failed');
    expect(breakdown.options.replacements.successTypes).toEqual([...SIGN_IN_SUCCESS_TYPES]);
    expect(breakdown.options.replacements.signInTypes).toEqual([
      ...SIGN_IN_SUCCESS_TYPES,
      ...SIGN_IN_FAILURE_TYPES,
    ]);
  });

  it('names a method for every sign-in type, and nothing else', async () => {
    answerWith({});

    await getSignInMetrics();

    const { replacements } = callFor('WITH presented').options;
    const named = [
      ...(replacements.passkeyTypes as string[]),
      ...(replacements.otpTypes as string[]),
      ...(replacements.magic_linkTypes as string[]),
      ...(replacements.oauthTypes as string[]),
      ...(replacements.totpTypes as string[]),
    ].sort();

    expect(named).toEqual([...SIGN_IN_SUCCESS_TYPES, ...SIGN_IN_FAILURE_TYPES].sort());
    expect(replacements.passkeyTypes).toEqual(['webauthn_login_success', 'webauthn_login_failed']);
    expect(replacements.otpTypes).toEqual(['verify_otp_success', 'verify_otp_failed']);
  });

  it('counts the steps as distinct attempts, only over rows that carry one', async () => {
    answerWith({});

    await getSignInMetrics();

    const attempts = callFor('COUNT(DISTINCT attempt_id)');

    expect(attempts.sql).toContain('WHERE attempt_id IS NOT NULL');
    expect(attempts.options.replacements).toMatchObject({
      startTypes: ['login_success', 'user_created'],
      deliveryTypes: ['otp_success', 'magic_link_requested'],
      successTypes: [...SIGN_IN_SUCCESS_TYPES],
    });
  });

  it('applies the window to both queries and leaves a missing bound out of the SQL', async () => {
    answerWith({});

    const from = new Date('2026-09-01T00:00:00.000Z');
    const to = new Date('2026-09-08T00:00:00.000Z');

    await getSignInMetrics({ from, to });

    for (const call of calls()) {
      expect(call.options.replacements).toMatchObject({ from, to });
      expect(call.sql).toContain('created_at >= :from');
      expect(call.sql).toContain('created_at <= :to');
    }

    query.mockClear();
    await getSignInMetrics({ from });

    for (const call of calls()) {
      expect(call.sql).toContain(':from');
      // A word boundary, since `:totpTypes` is bound in the same statement.
      expect(call.sql).not.toMatch(/:to\b/);
    }
  });

  it('surfaces a query failure instead of answering with zeros', async () => {
    query.mockRejectedValue(new Error('relation "auth_events" does not exist'));

    await expect(getSignInMetrics()).rejects.toThrow('auth_events');
  });
});
