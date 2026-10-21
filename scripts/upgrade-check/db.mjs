/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { createRequire } from 'module';
import pg from 'pg';

const require = createRequire(import.meta.url);
const { buildDatabaseUrl } = require('../../src/config/database.cjs');

export async function connect() {
  const client = new pg.Client({ connectionString: buildDatabaseUrl() });
  await client.connect();
  return client;
}

/**
 * Every row of every table, keyed by table and then by primary key, as `row_to_json`
 * renders it. `SequelizeMeta` is left out because migrating is meant to change it.
 */
export async function snapshot(client) {
  const { rows: tables } = await client.query(`
    SELECT c.relname AS name,
           array_agg(a.attname::text ORDER BY array_position(i.indkey, a.attnum)) AS pk
      FROM pg_index i
      JOIN pg_class c ON c.oid = i.indrelid
      JOIN pg_namespace n ON n.oid = c.relnamespace
      JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = ANY (i.indkey)
     WHERE i.indisprimary AND n.nspname = 'public' AND c.relname <> 'SequelizeMeta'
     GROUP BY c.relname
     ORDER BY c.relname`);

  const result = {};

  for (const { name, pk } of tables) {
    const { rows } = await client.query(`SELECT row_to_json(t) AS row FROM public."${name}" t`);
    result[name] = Object.fromEntries(
      rows.map(({ row }) => [JSON.stringify(pk.map((column) => row[column])), row]),
    );
  }

  return result;
}
