import { beforeEach, describe, expect, it, vi } from 'vitest';

import { getSystemConfig } from '../../../src/config/getSystemConfig.js';
import { Credential } from '../../../src/models/credentials.js';
import { getSequelize } from '../../../src/models/index.js';
import { PolicyDocumentSchema } from '../../../src/schemas/policy.schema.js';
import { normalizeLoginPolicy } from '../../../src/services/loginPolicyService.js';
import {
  breakGlassEmails,
  hasUsableFactor,
  POLICY_DRY_RUN_USER_CAP,
  runPolicyDryRun,
  signInRefusal,
} from '../../../src/services/policyDryRun.js';
import { buildSystemConfig } from '../../factories/systemConfigFactory.js';

vi.mock('../../../src/models/index.js', () => ({
  getSequelize: vi.fn(),
}));

const query = vi.fn();
const now = new Date('2026-10-22T12:00:00Z');

function policy(overrides: Record<string, unknown>) {
  return PolicyDocumentSchema.parse({
    login_methods: ['passkey', 'magic_link', 'email_otp', 'phone_otp', 'oauth'],
    passkey_login_fallback_enabled: true,
    ...overrides,
  });
}

function login(overrides: Record<string, unknown>) {
  return normalizeLoginPolicy(policy(overrides) as unknown as Record<string, unknown>);
}

const account = { email: 'a@example.com', phone: null, hasPasskey: false, oauthProviders: [] };

beforeEach(() => {
  vi.mocked(getSequelize).mockReturnValue({ query } as never);
  (Credential.findAll as any).mockResolvedValue([]);
  vi.mocked(getSystemConfig).mockResolvedValue(
    buildSystemConfig({
      oauth_providers: [
        { id: 'acme', enabled: true },
        { id: 'retired', enabled: false },
      ],
    }) as never,
  );
});

describe('signInRefusal', () => {
  it('admits every method the policy still enables', () => {
    const open = login({});

    for (const method of [
      'passkey',
      'magic_link',
      'email_otp',
      'phone_otp',
      'otp',
      'oauth',
      'totp',
    ]) {
      expect(signInRefusal(open, method as never, false)).toBeNull();
    }
  });

  it('refuses a method the policy no longer enables', () => {
    const passkeyOnly = login({ login_methods: ['passkey'] });

    expect(signInRefusal(passkeyOnly, 'magic_link', false)).toBe('method_disabled');
    expect(signInRefusal(passkeyOnly, 'oauth', false)).toBe('method_disabled');
    expect(signInRefusal(passkeyOnly, 'otp', false)).toBe('method_disabled');
    expect(signInRefusal(login({ login_methods: ['magic_link'] }), 'passkey', true)).toBe(
      'method_disabled',
    );
  });

  it('judges a code written before the channel was recorded against either code method', () => {
    expect(signInRefusal(login({ login_methods: ['phone_otp'] }), 'otp', false)).toBeNull();
  });

  it('refuses every other factor in phishing-resistant-only mode', () => {
    const strict = login({ phishing_resistant_only: true });

    expect(signInRefusal(strict, 'passkey', true)).toBeNull();
    expect(signInRefusal(strict, 'email_otp', true)).toBe('phishing_resistant_required');
    expect(signInRefusal(strict, 'totp', false)).toBe('phishing_resistant_required');
    expect(signInRefusal(strict, 'oauth', false)).toBe('phishing_resistant_required');
  });

  it('refuses a fallback for a passkey holder when fallback is off', () => {
    const noFallback = login({ passkey_login_fallback_enabled: false });

    expect(signInRefusal(noFallback, 'magic_link', true)).toBe('fallback_disabled');
    expect(signInRefusal(noFallback, 'totp', true)).toBe('fallback_disabled');
    expect(signInRefusal(noFallback, 'magic_link', false)).toBeNull();
    // OAuth completes without the ephemeral token the requirement is checked on.
    expect(signInRefusal(noFallback, 'oauth', true)).toBeNull();
  });
});

describe('hasUsableFactor', () => {
  const enabled = new Set(['acme']);

  it('is true while any address-based method still applies', () => {
    expect(hasUsableFactor(login({ login_methods: ['magic_link'] }), account, enabled)).toBe(true);
  });

  it('is false for an account with no passkey under a passkey-only policy', () => {
    expect(hasUsableFactor(login({ login_methods: ['passkey'] }), account, enabled)).toBe(false);
    expect(
      hasUsableFactor(
        login({ login_methods: ['passkey'] }),
        { ...account, hasPasskey: true },
        enabled,
      ),
    ).toBe(true);
  });

  it('counts a linked OAuth identity only while its provider is enabled', () => {
    const oauthOnly = login({ login_methods: ['oauth'] });
    const noEmail = { ...account, email: null };

    expect(hasUsableFactor(oauthOnly, { ...noEmail, oauthProviders: ['acme'] }, enabled)).toBe(
      true,
    );
    expect(hasUsableFactor(oauthOnly, { ...noEmail, oauthProviders: ['retired'] }, enabled)).toBe(
      false,
    );
    expect(
      hasUsableFactor(
        login({ login_methods: ['passkey'] }),
        { ...noEmail, oauthProviders: ['acme'] },
        enabled,
      ),
    ).toBe(false);
  });
});

describe('breakGlassEmails', () => {
  it('reads a trimmed, lower-cased list', () => {
    vi.stubEnv('BREAK_GLASS_EMAILS', ' Root@Example.com, ,ops@example.com ');

    expect([...breakGlassEmails()]).toEqual(['root@example.com', 'ops@example.com']);
  });

  it('is empty when unset', () => {
    vi.stubEnv('BREAK_GLASS_EMAILS', '');

    expect(breakGlassEmails().size).toBe(0);
  });
});

describe('runPolicyDryRun', () => {
  const row = (overrides: Record<string, unknown>) => ({
    userId: 'u-1',
    email: 'a@example.com',
    phone: null,
    method: 'magic_link',
    signIns: 1,
    hasPasskey: false,
    oauthProviders: [],
    ...overrides,
  });

  it('reports a passkey the candidate policy would not admit at enrollment, without a refused sign-in', async () => {
    query.mockResolvedValueOnce([
      row({
        userId: 'u-1',
        email: 'b@example.com',
        method: 'passkey',
        signIns: 2,
        hasPasskey: true,
      }),
    ]);
    (Credential.findAll as any).mockResolvedValueOnce([
      { userId: 'u-1', aaguid: null, deviceType: 'multiDevice', attestationType: 'none' },
    ]);

    const report = await runPolicyDryRun({
      policy: policy({ authenticator_policy: { syncedPasskeys: 'block' } }),
      days: 7,
      now,
    });

    expect(report.wouldFail).toEqual([
      {
        userId: 'u-1',
        email: 'b@example.com',
        signIns: 0,
        reasons: ['synced_passkey_blocked'],
        lockedOut: false,
      },
    ]);
    expect(Credential.findAll).toHaveBeenCalledWith(
      expect.objectContaining({ where: { userId: ['u-1'] } }),
    );
  });

  it('reports no authenticator reason for a passkey the policy admits', async () => {
    query.mockResolvedValueOnce([
      row({
        userId: 'u-1',
        email: 'b@example.com',
        method: 'passkey',
        signIns: 2,
        hasPasskey: true,
      }),
    ]);
    (Credential.findAll as any).mockResolvedValueOnce([
      { userId: 'u-1', aaguid: null, deviceType: 'singleDevice', attestationType: 'none' },
    ]);

    const report = await runPolicyDryRun({
      policy: policy({ authenticator_policy: { syncedPasskeys: 'block' } }),
      days: 7,
      now,
    });

    expect(report.wouldFail).toEqual([]);
  });

  it('reports refused sign-ins, lockouts first, over a bounded window', async () => {
    query.mockResolvedValueOnce([
      row({
        userId: 'u-1',
        email: 'b@example.com',
        method: 'magic_link',
        signIns: 3,
        hasPasskey: true,
      }),
      row({
        userId: 'u-1',
        email: 'b@example.com',
        method: 'passkey',
        signIns: 2,
        hasPasskey: true,
      }),
      row({ userId: 'u-2', email: 'c@example.com', method: 'email_otp', signIns: 1 }),
      row({
        userId: 'u-3',
        email: 'z@example.com',
        method: 'oauth',
        signIns: 4,
        oauthProviders: null,
      }),
    ]);

    const report = await runPolicyDryRun({
      policy: policy({
        login_methods: ['passkey', 'magic_link'],
        passkey_login_fallback_enabled: false,
      }),
      days: 7,
      now,
    });

    const [sql, options] = query.mock.calls[0];
    expect(String(sql)).toContain('LIMIT :cap');
    expect(options.replacements).toMatchObject({
      from: new Date('2026-10-15T12:00:00Z'),
      to: now,
      cap: POLICY_DRY_RUN_USER_CAP + 1,
    });
    expect(report).toEqual({
      window: { from: '2026-10-15T12:00:00.000Z', to: now.toISOString() },
      signInsEvaluated: 10,
      usersEvaluated: 3,
      wouldFail: [
        {
          userId: 'u-2',
          email: 'c@example.com',
          signIns: 1,
          reasons: ['method_disabled'],
          lockedOut: false,
        },
        {
          userId: 'u-1',
          email: 'b@example.com',
          signIns: 3,
          reasons: ['fallback_disabled'],
          lockedOut: false,
        },
        {
          userId: 'u-3',
          email: 'z@example.com',
          signIns: 4,
          reasons: ['method_disabled'],
          lockedOut: false,
        },
      ].sort((a, b) => a.email.localeCompare(b.email)),
      usersLockedOut: 0,
      breakGlassAccounts: 0,
      capped: false,
    });
  });

  it('flags an account with nothing left to sign in with', async () => {
    query.mockResolvedValueOnce([
      row({ userId: 'u-1', email: 'a@example.com', method: 'email_otp' }),
      row({ userId: 'u-2', email: 'b@example.com', method: 'magic_link', hasPasskey: true }),
    ]);

    const report = await runPolicyDryRun({
      policy: policy({ phishing_resistant_only: true }),
      days: 1,
      now,
    });

    expect(report.wouldFail.map((user) => [user.userId, user.lockedOut])).toEqual([
      ['u-1', true],
      ['u-2', false],
    ]);
    expect(report.wouldFail[0].reasons).toEqual(['phishing_resistant_required']);
    expect(report.usersLockedOut).toBe(1);
  });

  it('counts break-glass accounts and never lists them', async () => {
    vi.stubEnv('BREAK_GLASS_EMAILS', 'Root@example.com');
    query
      .mockResolvedValueOnce([
        row({ userId: 'u-1', email: 'root@example.com', method: 'magic_link' }),
        row({ userId: 'u-2', email: 'b@example.com', method: 'magic_link' }),
      ])
      .mockResolvedValueOnce([{ count: 1 }]);

    const report = await runPolicyDryRun({
      policy: policy({ login_methods: ['passkey'] }),
      days: 7,
      now,
    });

    expect(report.wouldFail.map((user) => user.userId)).toEqual(['u-2']);
    expect(report.usersEvaluated).toBe(1);
    expect(report.breakGlassAccounts).toBe(1);
    expect(query.mock.calls[1][1].replacements).toEqual({ emails: ['root@example.com'] });
  });

  it('answers zero break-glass accounts when the count query returns nothing', async () => {
    vi.stubEnv('BREAK_GLASS_EMAILS', 'root@example.com');
    query.mockResolvedValueOnce([]).mockResolvedValueOnce([]);

    const report = await runPolicyDryRun({ policy: policy({}), days: 7, now });

    expect(report.breakGlassAccounts).toBe(0);
  });

  it('evaluates at most the cap and says it was reached', async () => {
    query.mockResolvedValueOnce([
      row({ userId: 'u-1' }),
      row({ userId: 'u-2', email: null }),
      row({ userId: 'u-3' }),
    ]);

    const report = await runPolicyDryRun({
      policy: policy({ login_methods: ['passkey'] }),
      days: 7,
      now,
      cap: 2,
    });

    expect(report.capped).toBe(true);
    expect(report.usersEvaluated).toBe(2);
    expect(report.wouldFail.map((user) => user.userId)).toEqual(['u-2', 'u-1']);
    expect(report.wouldFail[0].email).toBe('');
  });

  it('defaults the window end to now', async () => {
    query.mockResolvedValueOnce([]);

    const report = await runPolicyDryRun({ policy: policy({}), days: 30 });

    expect(Date.parse(report.window.to) - Date.parse(report.window.from)).toBe(30 * 86_400_000);
  });
});
