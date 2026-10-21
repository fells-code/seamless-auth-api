import { randomUUID } from 'crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { bootstrapSystemConfig } from '../../src/config/bootstrapSystemConfig.js';
import { getDatabaseSize } from '../../src/controllers/admin.js';
import { getSequelize, initializeModels } from '../../src/models/index.js';
import { streamAuthEventExport } from '../../src/services/auditExport.js';
import { buildCoverageReport } from '../../src/services/coverageReport.js';
import { listEnrollment } from '../../src/services/enrollmentService.js';
import { getFunnelMetrics } from '../../src/services/funnelMetrics.js';
import { getReviewAccounts } from '../../src/services/reviewAccountUsage.js';
import { findPendingMigrations } from '../../src/services/schemaGuard.js';
import { getSignInMetrics } from '../../src/services/signInMetrics.js';
import { buildSystemConfig } from '../factories/systemConfigFactory.js';

// Everything is seeded in March 2001 and every query is windowed to it, so rows the other
// files write do not reach these figures.
const at = (time: string) => new Date(`2001-03-05T${time}.000Z`);
const window = { from: new Date('2001-03-01T00:00:00Z'), to: new Date('2001-03-31T00:00:00Z') };

const enrolled = randomUUID();
const pending = randomUUID();
const organization = randomUUID();
const registration = randomUUID();
const login = randomUUID();

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

function event(type: string, userId: string | null, time: string, extra = {}) {
  return insert('auth_events', {
    id: randomUUID(),
    user_id: userId,
    type,
    device_class: 'desktop',
    created_at: at(time),
    updated_at: at(time),
    ...extra,
  });
}

function user(id: string, email: string) {
  return insert('users', {
    id,
    email,
    roles: '{user}',
    created_at: at('10:00:00'),
    updated_at: at('10:00:00'),
  });
}

beforeAll(async () => {
  await initializeModels();

  // The keys with no default, as an operator would seed them; bootstrap fills in the rest.
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

  await user(enrolled, `enrolled-${enrolled}@example.com`);
  await user(pending, `pending-${pending}@example.com`);

  await insert('credentials', {
    id: `cred-${enrolled}`,
    userId: enrolled,
    publicKey: Buffer.from('public-key'),
    deviceType: 'multiDevice',
    backedup: true,
    createdAt: at('10:05:00'),
    updatedAt: at('10:05:00'),
  });

  await insert('organizations', {
    id: organization,
    name: 'Postgres Suite',
    slug: `postgres-suite-${organization}`,
    created_at: at('09:00:00'),
    updated_at: at('09:00:00'),
  });

  for (const member of [enrolled, pending]) {
    await insert('organization_memberships', {
      id: randomUUID(),
      organization_id: organization,
      user_id: member,
      created_at: at('10:00:00'),
      updated_at: at('10:00:00'),
    });
  }

  // Registration: account created, code sent, code verified (written twice, as it is).
  await event('user_created', enrolled, '10:00:00', { attempt_id: registration });
  await event('otp_success', enrolled, '10:00:10', { attempt_id: registration });
  await event('verify_otp_success', enrolled, '10:01:00', {
    attempt_id: registration,
    metadata: { channel: 'email', reviewAccount: 'true' },
  });
  await event('verify_otp_success', enrolled, '10:01:00', {
    attempt_id: registration,
    metadata: { channel: 'email', reviewAccount: 'true' },
  });

  // Login: one failed passkey assertion, then a successful one, in the same attempt.
  await event('login_success', pending, '11:00:00', { attempt_id: login });
  await event('webauthn_login_failed', pending, '11:00:30', { attempt_id: login });
  await event('webauthn_login_success', pending, '11:00:40', { attempt_id: login });

  // A magic link failure from before attempt ids were recorded.
  await event('magic_link_failed', null, '12:00:00');
});

afterAll(async () => {
  await getSequelize().close();
});

describe('raw SQL services against the migrated schema', () => {
  it('sign-in metrics fold events by attempt and method', async () => {
    const metrics = await getSignInMetrics(window);

    expect(metrics.attempts).toEqual({ started: 2, delivered: 1, presented: 2, completed: 2 });
    expect(metrics.signIns).toEqual({ success: 2, failed: 1, successRate: 2 / 3 });
    expect(
      metrics.breakdown.map(({ method, success, failed }) => ({ method, success, failed })),
    ).toEqual([
      { method: 'magic_link', success: 0, failed: 1 },
      { method: 'otp', success: 1, failed: 0 },
      { method: 'passkey', success: 1, failed: 0 },
    ]);
  });

  it('funnel metrics measure registration, login and passkey adoption', async () => {
    const funnel = await getFunnelMetrics(window);

    expect(funnel.timeToRegistration).toEqual({ count: 1, medianSeconds: 60, p90Seconds: 60 });
    expect(funnel.timeToLogin).toEqual({ count: 1, medianSeconds: 40, p90Seconds: 40 });
    expect(funnel.passkeyAdoption).toEqual({ users: 2, withPasskey: 1, rate: 0.5 });
    expect(funnel.timeToFirstPasskey).toMatchObject({ count: 1, medianSeconds: 300 });
  });

  it('the coverage report reads users, credentials, organizations and sign-ins', async () => {
    const report = await buildCoverageReport(
      { from: '2001-03-01', to: '2001-03-31', organizationId: organization, bucket: 'week' },
      new Date('2001-04-01T00:00:00Z'),
    );

    expect(report.coverage).toEqual({ users: 2, passkeyUsers: 1, percent: 50 });
    // The first week closes at midnight on Monday 5 March, before either account existed.
    expect(report.trend[0]).toMatchObject({ end: '2001-03-04', users: 0, passkeyUsers: 0 });
    expect(report.trend[1]).toMatchObject({ users: 2, passkeyUsers: 1 });
    expect(report.byOrganization).toEqual([
      {
        organizationId: organization,
        name: 'Postgres Suite',
        users: 2,
        passkeyUsers: 1,
        percent: 50,
      },
    ]);
    expect(report.authenticatorMix).toEqual([
      expect.objectContaining({ credentials: 1, users: 1, backupEligible: 1, backedUp: 1 }),
    ]);
    expect(report.signInMix.total).toBe(2);
  });

  it('enrollment lists an organization by credential count', async () => {
    const result = await listEnrollment({ organizationId: organization, limit: 10, offset: 0 });

    expect(result.summary).toEqual({ total: 2, none: 1, one: 1, twoOrMore: 0 });
    expect(result.users.map((row) => [row.id, row.credentialCount])).toEqual(
      expect.arrayContaining([
        [enrolled, 1],
        [pending, 0],
      ]),
    );
  });

  it('review account usage counts flagged sign-ins once per attempt', async () => {
    const usage = await getReviewAccounts({ days: 30 }, new Date('2001-03-31T00:00:00Z'));

    expect(usage.recentSignIns).toMatchObject({ count: 1, failedVerifications: 0 });
  });

  it('the audit export is a contiguous, linked run of the chain', async () => {
    const lines: string[] = [];
    const manifest = await streamAuthEventExport({
      from: window.from,
      to: window.to,
      write: (line) => void lines.push(line),
    });
    const events = lines.slice(0, -1).map((line) => JSON.parse(line));

    expect(manifest.count).toBe(events.length);
    expect(events.length).toBeGreaterThanOrEqual(8);
    events.slice(1).forEach((exported, index) => {
      expect(exported.seq).toBe(events[index].seq + 1);
      expect(exported.prevHash).toBe(events[index].hash);
    });
    expect(manifest.lastHash).toBe(events[events.length - 1].hash);
  });

  it('the schema guard finds no pending migrations', async () => {
    expect(await findPendingMigrations(getSequelize())).toEqual([]);
  });

  it('reports the database size', async () => {
    expect(await getDatabaseSize()).toBeGreaterThan(0);
  });
});
