/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

/**
 * Checks that the current migrations kept the data seed.mjs wrote on the previous
 * release's schema, and that this build can run against the result.
 *
 * Usage: npx tsx scripts/upgrade-check/verify.mjs <snapshot.json>
 */

import { readFile } from 'fs/promises';

import { bootstrapSystemConfig } from '../../src/config/bootstrapSystemConfig.js';
import { getSystemConfig } from '../../src/config/getSystemConfig.js';
import { getSequelize, initializeModels } from '../../src/models/index.js';
import { verifyAuthEventChain } from '../../src/services/auditIntegrity.js';
import { findPendingMigrations } from '../../src/services/schemaGuard.js';
import { connect, snapshot } from './db.mjs';

/**
 * Values a migration is meant to change or remove, as `table` or `table.column`, with the
 * reason. Anything else that differs from the snapshot fails the check.
 */
const EXPECTED_CHANGES = {};

const failures = [];
const describe = (error) => error?.parent?.message ?? error?.stack ?? String(error);
const fail = (message) => failures.push(message);
const expected = (table, column) =>
  EXPECTED_CHANGES[table] ?? (column && EXPECTED_CHANGES[`${table}.${column}`]);

function compare(before, after) {
  for (const [table, rows] of Object.entries(before)) {
    if (!after[table]) {
      if (!expected(table)) fail(`${table}: table is gone`);
      continue;
    }

    for (const [key, row] of Object.entries(rows)) {
      const now = after[table][key];

      if (!now) {
        if (!expected(table)) fail(`${table} ${key}: row is gone`);
        continue;
      }

      for (const [column, value] of Object.entries(row)) {
        if (!(column in now)) {
          if (!expected(table, column)) fail(`${table}.${column}: column is gone`);
        } else if (JSON.stringify(now[column]) !== JSON.stringify(value)) {
          if (!expected(table, column)) {
            fail(
              `${table}.${column} ${key}: ${JSON.stringify(value)} became ${JSON.stringify(now[column])}`,
            );
          }
        }
      }
    }

    console.log(`${table}: ${Object.keys(rows).length} rows checked`);
  }
}

const [path] = process.argv.slice(2);

if (!path) {
  console.error('Usage: npx tsx scripts/upgrade-check/verify.mjs <snapshot.json>');
  process.exit(2);
}

const before = JSON.parse(await readFile(path, 'utf8'));
const client = await connect();
try {
  compare(before, await snapshot(client));
} finally {
  await client.end();
}

const models = await initializeModels();
const sequelize = getSequelize();

try {
  const pending = await findPendingMigrations(sequelize);
  if (pending.length) fail(`pending migrations after upgrade: ${pending.join(', ')}`);

  const chain = await verifyAuthEventChain();
  const seededEvents = Object.keys(before.auth_events ?? {}).length;
  if (!chain.verified) fail(`audit chain does not verify: ${JSON.stringify(chain.firstFailure)}`);
  if (chain.rowsChecked !== seededEvents) {
    fail(`audit chain holds ${chain.rowsChecked} events, ${seededEvents} were seeded`);
  }

  // What the server does at boot: fill in new config keys, then parse the whole set.
  await bootstrapSystemConfig();
  await getSystemConfig();

  // Every model selects all of its attributes, so one the schema lacks fails here.
  for (const [name, model] of Object.entries(models)) {
    if (typeof model?.findAll === 'function' && name !== 'sequelize') {
      await model.findAll({ limit: 1 }).catch((error) => fail(`${name}: ${describe(error)}`));
    }
  }

  if ((await models.User.count()) !== Object.keys(before.users).length) {
    fail('the User model does not see every seeded user');
  }

  await models.AuthEvent.create({ type: 'informational', metadata: { upgradeCheck: true } });
  const extended = await verifyAuthEventChain();
  if (!extended.verified || extended.rowsChecked !== seededEvents + 1) {
    fail(`audit chain does not verify after a new event: ${JSON.stringify(extended)}`);
  }
} catch (error) {
  fail(describe(error));
} finally {
  await sequelize.close();
}

if (failures.length) {
  console.error(`Upgrade check failed:\n  ${failures.join('\n  ')}`);
  process.exit(1);
}

console.log('Upgrade check passed: seeded data survived and the chain verifies.');
