/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

/**
 * Seeds a database migrated to the previous release with the rows a running deployment
 * holds, then writes a snapshot of every table for verify.mjs to compare after the
 * current migrations have run.
 *
 * Usage: node scripts/upgrade-check/seed.mjs <snapshot.json>
 *
 * Only columns the previous schema has are written, so a column a later migration drops
 * does not need a change here once that migration has been released.
 */

import { writeFile } from 'fs/promises';

import { connect, snapshot } from './db.mjs';

const ALICE = '00000000-0000-4000-8000-00000000a11c';
const BOB = '00000000-0000-4000-8000-000000000b0b';
const CAROL = '00000000-0000-4000-8000-0000000ca201';
const ORG = '00000000-0000-4000-8000-0000000000a1';
const SESSION_OLD = '00000000-0000-4000-8000-000000005e01';
const SESSION_NEW = '00000000-0000-4000-8000-000000005e02';

const day = (n) => new Date(Date.UTC(2026, 0, n, 9, 30)).toISOString();
const stamps = (n) => ({ createdAt: day(n), updatedAt: day(n) });
const snake = (n) => ({ created_at: day(n), updated_at: day(n) });

const ROWS = {
  users: [
    {
      id: ALICE,
      email: 'alice@example.com',
      phone: '+14155550101',
      roles: '{user,admin}',
      verified: true,
      email_verified: true,
      phone_verified: true,
      last_login: day(20),
      ...snake(1),
    },
    { id: BOB, email: 'bob@example.com', roles: '{user}', verified: true, ...snake(2) },
    { id: CAROL, email: 'carol@example.com', roles: '{user}', revoked: true, ...snake(3) },
  ],
  credentials: [
    {
      id: 'Y3JlZGVudGlhbC1hbGljZS0x',
      userId: ALICE,
      publicKey: Buffer.from('a5010203262001215820', 'hex'),
      counter: 7,
      transports: JSON.stringify(['internal', 'hybrid']),
      backedup: true,
      deviceType: 'multiDevice',
      friendlyName: 'Laptop',
      lastUsedAt: day(20),
      platform: 'macOS',
      browser: 'Safari',
      prfCapable: true,
      aaguid: 'fbfc3007-154e-4ecc-8c0b-6e020557d7bd',
      attestationFormat: 'none',
      ...stamps(4),
    },
    {
      id: 'Y3JlZGVudGlhbC1ib2ItMQ',
      userId: BOB,
      publicKey: Buffer.from('a50102032620012158ff', 'hex'),
      counter: 0,
      deviceType: 'singleDevice',
      ...stamps(5),
    },
  ],
  totp_credentials: [
    {
      id: '00000000-0000-4000-8000-0000000070a1',
      userId: ALICE,
      secretCiphertext: 'c2VjcmV0LWNpcGhlcnRleHQ=',
      secretIv: 'aXYtMTIzNDU2Nzg=',
      secretTag: 'dGFnLTEyMzQ1Njc4',
      issuer: 'Seamless',
      accountName: 'alice@example.com',
      enabled: true,
      verifiedAt: day(6),
      lastUsedCounter: 59000000,
      ...stamps(6),
    },
  ],
  organizations: [
    {
      id: ORG,
      name: 'Acme',
      slug: 'acme',
      created_by_user_id: ALICE,
      metadata: JSON.stringify({ plan: 'pilot' }),
      ...snake(7),
    },
  ],
  organization_memberships: [
    {
      id: '00000000-0000-4000-8000-00000000e301',
      organization_id: ORG,
      user_id: ALICE,
      roles: JSON.stringify(['owner']),
      ...snake(7),
    },
    {
      id: '00000000-0000-4000-8000-00000000e302',
      organization_id: ORG,
      user_id: BOB,
      ...snake(8),
    },
  ],
  sessions: [
    {
      id: SESSION_OLD,
      userId: ALICE,
      infraId: 'upgrade-check',
      mode: 'web',
      userAgent: 'Mozilla/5.0 (Macintosh)',
      ipAddress: '203.0.113.10',
      lastUsedAt: day(19),
      expiresAt: day(40),
      idleExpiresAt: day(25),
      replacedBySessionId: SESSION_NEW,
      revokedAt: day(19),
      revokedReason: 'rotated',
      refreshTokenLookup: 'a'.repeat(64),
      organizationId: ORG,
      chainStartedAt: day(18),
      ...stamps(18),
    },
    {
      id: SESSION_NEW,
      userId: ALICE,
      infraId: 'upgrade-check',
      mode: 'web',
      lastUsedAt: day(20),
      expiresAt: day(41),
      idleExpiresAt: day(26),
      refreshTokenLookup: 'b'.repeat(64),
      stepUpVerifiedAt: day(20),
      stepUpMethod: 'passkey',
      organizationId: ORG,
      chainStartedAt: day(18),
      ...stamps(19),
    },
  ],
  magic_link_tokens: [
    {
      id: '00000000-0000-4000-8000-0000000003a1',
      user_id: BOB,
      token_hash: 'c'.repeat(64),
      redirect_url: 'https://app.example.com/welcome',
      expires_at: day(10),
      used_at: day(9),
      created_at: day(9),
    },
  ],
  oauth_identities: [
    {
      id: '00000000-0000-4000-8000-0000000000a7',
      user_id: BOB,
      provider_id: 'github',
      provider_subject: '424242',
      email: 'bob@example.com',
      profile: JSON.stringify({ login: 'bob' }),
      ...snake(11),
    },
  ],
  user_external_ids: [
    {
      id: '00000000-0000-4000-8000-0000000000e1',
      user_id: BOB,
      source: 'okta',
      external_id: '00u1abcd',
      ...snake(12),
    },
  ],
  auth_failures: [
    {
      id: '00000000-0000-4000-8000-0000000000f1',
      user_id: BOB,
      type: 'otp',
      occurred_at: day(13),
      ...snake(13),
    },
  ],
  system_config: [
    ['app_name', 'Upgrade Check'],
    ['default_roles', ['user']],
    ['available_roles', ['user', 'admin']],
    ['access_token_ttl', '15m'],
    ['refresh_token_ttl', '7d'],
    ['session_idle_ttl', '8h'],
    ['rate_limit', 100],
    ['delay_after', 50],
    ['rpid', 'localhost'],
    ['origins', ['http://localhost:5174']],
    ['frontend_url', 'http://localhost:5174'],
  ].map(([key, value]) => ({ key, value: JSON.stringify(value), updatedBy: ALICE, ...stamps(1) })),
};

// Written in this order so the previous release's trigger chains them in it.
const EVENTS = [
  ['user_created', ALICE, { method: 'passkey' }],
  ['registration_success', ALICE, null],
  ['login_success', ALICE, null],
  ['webauthn_login_success', ALICE, { credentialId: 'Y3JlZGVudGlhbC1hbGljZS0x' }],
  ['user_created', BOB, null],
  ['otp_success', BOB, { channel: 'email' }],
  ['verify_otp_failed', BOB, { channel: 'email' }],
  ['verify_otp_success', BOB, { channel: 'email' }],
  ['magic_link_requested', BOB, null],
  ['magic_link_poll_completed_successfully', BOB, null],
  ['refresh_token_success', ALICE, null],
  ['internal_user_updated_by_owner', CAROL, { revoked: true }],
].map(([type, userId, metadata], index) => ({
  id: `00000000-0000-4000-8000-${String(index + 1).padStart(12, '0')}`,
  user_id: userId,
  actor_user_id: type === 'internal_user_updated_by_owner' ? ALICE : null,
  session_id: type === 'refresh_token_success' ? SESSION_NEW : null,
  type,
  ip_address: '203.0.113.10',
  user_agent: 'Mozilla/5.0 (Macintosh)',
  deployment_id: 'upgrade-check',
  device_class: 'desktop',
  mail_provider: 'other',
  owner: userId === ALICE,
  attempt_id: null,
  metadata: metadata && JSON.stringify(metadata),
  created_at: new Date(Date.UTC(2026, 0, 14, 9, index)).toISOString(),
  updated_at: new Date(Date.UTC(2026, 0, 14, 9, index)).toISOString(),
}));

async function columnsOf(client, table) {
  const { rows } = await client.query(
    `SELECT column_name FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name = $1`,
    [table],
  );
  return new Set(rows.map((row) => row.column_name));
}

async function insertAll(client, table, rows) {
  const columns = await columnsOf(client, table);

  if (columns.size === 0) {
    console.log(`skip ${table}: not in the previous schema`);
    return;
  }

  for (const row of rows) {
    const entries = Object.entries(row).filter(([column]) => columns.has(column));
    await client.query(
      `INSERT INTO public."${table}" (${entries.map(([c]) => `"${c}"`).join(', ')})
       VALUES (${entries.map((_, i) => `$${i + 1}`).join(', ')})
       ${table === 'system_config' ? 'ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, "updatedBy" = EXCLUDED."updatedBy"' : ''}`,
      entries.map(([, value]) => value),
    );
  }

  console.log(`seeded ${table}: ${rows.length}`);
}

const [out] = process.argv.slice(2);

if (!out) {
  console.error('Usage: node scripts/upgrade-check/seed.mjs <snapshot.json>');
  process.exit(2);
}

const client = await connect();

try {
  await client.query('BEGIN');
  for (const [table, rows] of Object.entries(ROWS)) {
    await insertAll(client, table, rows);
  }
  await insertAll(client, 'auth_events', EVENTS);
  await client.query('COMMIT');

  const tables = await snapshot(client);
  await writeFile(out, JSON.stringify(tables, null, 2));
  console.log(`snapshot of ${Object.keys(tables).length} tables written to ${out}`);
} finally {
  await client.end();
}
