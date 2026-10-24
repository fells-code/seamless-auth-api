import { randomUUID } from 'crypto';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

import { bootstrapSystemConfig } from '../../src/config/bootstrapSystemConfig.js';
import { getSequelize, initializeModels } from '../../src/models/index.js';
import { PolicyVersion } from '../../src/models/policyVersions.js';
import { SystemConfig } from '../../src/models/systemConfig.js';
import { PolicyDocumentSchema } from '../../src/schemas/policy.schema.js';
import { runPolicyDryRun } from '../../src/services/policyDryRun.js';
import {
  getPolicyState,
  listPolicyVersions,
  lockPolicyForConfigPatch,
  PolicyVersionConflictError,
  publishPolicyDraft,
  recordBootstrapPolicyVersion,
  recordConfigPatchPolicyVersion,
  rollbackPolicy,
  savePolicyDraft,
} from '../../src/services/policyVersionService.js';
import { buildSystemConfig } from '../factories/systemConfigFactory.js';

const admin = randomUUID();

const passkeyOnly = PolicyDocumentSchema.parse({
  login_methods: ['passkey'],
  passkey_login_fallback_enabled: false,
});

async function insert(table: string, row: Record<string, unknown>) {
  const columns = Object.keys(row);
  await getSequelize().query(
    `INSERT INTO ${table} (${columns.map((column) => `"${column}"`).join(', ')})
     VALUES (${columns.map((column) => `:${column}`).join(', ')})`,
    {
      replacements: Object.fromEntries(
        Object.entries(row).map(([key, value]) => [
          key,
          value !== null && typeof value === 'object' && !(value instanceof Date)
            ? JSON.stringify(value)
            : value,
        ]),
      ),
    },
  );
}

async function storedLoginMethods() {
  const row = await SystemConfig.findByPk('login_methods');
  return row?.value;
}

beforeAll(async () => {
  await initializeModels();

  for (const [key, value] of Object.entries(
    buildSystemConfig({ frontend_url: 'http://localhost:5174' }),
  )) {
    await getSequelize().query(
      `INSERT INTO system_config (key, value, "createdAt", "updatedAt")
       VALUES (:key, :value, now(), now())
       ON CONFLICT (key) DO NOTHING`,
      { replacements: { key, value: JSON.stringify(value) } },
    );
  }
  await bootstrapSystemConfig();
  await recordBootstrapPolicyVersion();
});

afterAll(async () => {
  await getSequelize().close();
});

describe('policy versions against the migrated schema', () => {
  it('records the policy in force at boot, once', async () => {
    const before = await listPolicyVersions();

    expect(before.length).toBeGreaterThan(0);
    expect(await recordBootstrapPolicyVersion()).toBeNull();
    expect(await listPolicyVersions()).toHaveLength(before.length);
  });

  it('rolls a publish back completely when it fails part way', async () => {
    const { published } = await getPolicyState();
    const loginMethodsBefore = await storedLoginMethods();

    await savePolicyDraft(passkeyOnly, admin);

    // Fails after every system_config row has been written in the transaction.
    const create = vi.spyOn(PolicyVersion, 'create').mockRejectedValueOnce(new Error('disk full'));

    await expect(
      publishPolicyDraft({ expectedVersion: published.version, actor: admin }),
    ).rejects.toThrow('disk full');
    create.mockRestore();

    const after = await getPolicyState();
    expect(after.published.version).toBe(published.version);
    expect(after.draft?.policy).toEqual(passkeyOnly);
    expect(await storedLoginMethods()).toEqual(loginMethodsBefore);
  });

  it('lets one of two concurrent publishes through and refuses the other', async () => {
    const { published } = await getPolicyState();

    await savePolicyDraft(passkeyOnly, admin);

    const results = await Promise.allSettled([
      publishPolicyDraft({ expectedVersion: published.version, actor: admin }),
      publishPolicyDraft({ expectedVersion: published.version, actor: admin }),
    ]);

    const fulfilled = results.filter((result) => result.status === 'fulfilled');
    const rejected = results.filter((result) => result.status === 'rejected');

    expect(fulfilled).toHaveLength(1);
    expect(rejected).toHaveLength(1);
    expect((rejected[0] as PromiseRejectedResult).reason).toBeInstanceOf(
      PolicyVersionConflictError,
    );

    const after = await getPolicyState();
    expect(after.published).toMatchObject({
      version: published.version + 1,
      source: 'publish',
      publishedBy: admin,
      policy: passkeyOnly,
    });
    expect(after.draft).toBeNull();
    expect(await storedLoginMethods()).toEqual(['passkey']);

    const row = await SystemConfig.findByPk('login_methods');
    expect(row?.updatedBy).toBe(admin);
  });

  it('rolls back by publishing a copy of an older version', async () => {
    const versions = await listPolicyVersions();
    const [current] = versions;
    const target = versions[versions.length - 1];

    const { published } = await rollbackPolicy({
      version: target.version,
      expectedVersion: current.version,
      actor: admin,
    });

    expect(published.version).toBe(current.version + 1);
    expect(published.rolledBackTo).toBe(target.version);
    expect(await storedLoginMethods()).toEqual(target.policy.login_methods);
    expect((await listPolicyVersions())[0]).toMatchObject({
      version: current.version + 1,
      source: 'rollback',
      rolledBackTo: target.version,
    });
  });

  it('versions a whole-config patch that changes the policy in its transaction', async () => {
    const { published } = await getPolicyState();

    const recorded = await getSequelize().transaction(async (tx) => {
      await lockPolicyForConfigPatch(tx);
      await SystemConfig.upsert(
        {
          key: 'passkey_login_fallback_enabled',
          value: !published.policy.passkey_login_fallback_enabled,
          updatedBy: admin,
        },
        { transaction: tx },
      );
      return recordConfigPatchPolicyVersion(tx, admin);
    });

    expect(recorded?.version).toBe(published.version + 1);
    expect((await getPolicyState()).published).toMatchObject({
      source: 'config_patch',
      policy: {
        passkey_login_fallback_enabled: !published.policy.passkey_login_fallback_enabled,
      },
    });
  });

  it('refuses a second draft row', async () => {
    await expect(
      insert('policy_drafts', { id: 2, policy: passkeyOnly, based_on_version: 1 }),
    ).rejects.toThrow(/policy_drafts_single_row/);
  });
});

describe('policy dry run against the migrated schema', () => {
  // Seeded in May 2001 and windowed to it, so rows the other files write stay out.
  const now = new Date('2001-05-08T00:00:00Z');
  const at = (day: number, time = '10:00:00') => new Date(`2001-05-0${day}T${time}.000Z`);

  const holder = randomUUID();
  const emailOnly = randomUUID();
  const revoked = randomUUID();
  const newcomer = randomUUID();
  const breakGlass = randomUUID();

  async function user(id: string, email: string, extra = {}) {
    await insert('users', {
      id,
      email,
      roles: '{user}',
      created_at: at(1),
      updated_at: at(1),
      ...extra,
    });
  }

  async function event(type: string, userId: string, time: Date, extra = {}) {
    await insert('auth_events', {
      id: randomUUID(),
      user_id: userId,
      type,
      created_at: time,
      updated_at: time,
      ...extra,
    });
  }

  beforeAll(async () => {
    await user(holder, `holder-${holder}@example.com`);
    await user(emailOnly, `email-${emailOnly}@example.com`);
    await user(revoked, `revoked-${revoked}@example.com`, { revoked: true });
    await user(newcomer, `new-${newcomer}@example.com`);
    await user(breakGlass, `root-${breakGlass}@example.com`);

    await insert('credentials', {
      id: `cred-${holder}`,
      userId: holder,
      publicKey: Buffer.from('public-key'),
      deviceType: 'multiDevice',
      backedup: true,
      createdAt: at(1),
      updatedAt: at(1),
    });

    // Two magic link sign-ins and a passkey one for the passkey holder.
    await event('magic_link_poll_completed_successfully', holder, at(2), {
      attempt_id: randomUUID(),
    });
    await event('magic_link_poll_completed_successfully', holder, at(3), {
      attempt_id: randomUUID(),
    });
    await event('webauthn_login_success', holder, at(4), { attempt_id: randomUUID() });

    // An email code sign-in written twice in one attempt, as the OTP flow does.
    const otpAttempt = randomUUID();
    await event('verify_otp_success', emailOnly, at(5), {
      attempt_id: otpAttempt,
      metadata: { channel: 'email' },
    });
    await event('verify_otp_success', emailOnly, at(5, '10:00:05'), {
      attempt_id: otpAttempt,
      metadata: { channel: 'email' },
    });
    // TOTP enrolment, not a sign-in.
    await event('totp_success', emailOnly, at(5), { metadata: { flow: 'enrollment' } });
    // Outside the window.
    await event(
      'magic_link_poll_completed_successfully',
      emailOnly,
      new Date('2001-04-20T10:00:00Z'),
    );

    await event('magic_link_poll_completed_successfully', revoked, at(5));

    // A registration attempt verifying the new account's address.
    const registration = randomUUID();
    await event('user_created', newcomer, at(6), { attempt_id: registration });
    await event('verify_otp_success', newcomer, at(6, '10:01:00'), {
      attempt_id: registration,
      metadata: { channel: 'email' },
    });

    await event('magic_link_poll_completed_successfully', breakGlass, at(6));
  });

  it('reports the sign-ins a passkey-only policy would refuse', async () => {
    vi.stubEnv('BREAK_GLASS_EMAILS', `ROOT-${breakGlass}@example.com`);

    const report = await runPolicyDryRun({ policy: passkeyOnly, days: 7, now });

    expect(report.window).toEqual({
      from: '2001-05-01T00:00:00.000Z',
      to: '2001-05-08T00:00:00.000Z',
    });
    expect(report.usersEvaluated).toBe(2);
    expect(report.signInsEvaluated).toBe(4);
    expect(report.breakGlassAccounts).toBe(1);
    expect(report.capped).toBe(false);
    expect(report.wouldFail).toEqual([
      {
        userId: emailOnly,
        email: `email-${emailOnly}@example.com`,
        signIns: 1,
        reasons: ['method_disabled'],
        lockedOut: true,
      },
      {
        userId: holder,
        email: `holder-${holder}@example.com`,
        signIns: 2,
        reasons: ['method_disabled'],
        lockedOut: false,
      },
    ]);
    expect(report.usersLockedOut).toBe(1);
  });

  it('stops at the cap', async () => {
    const report = await runPolicyDryRun({ policy: passkeyOnly, days: 7, now, cap: 1 });

    expect(report.capped).toBe(true);
    expect(report.usersEvaluated).toBeLessThanOrEqual(1);
  });
});
