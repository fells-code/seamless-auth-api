import { mkdtemp, readFile, rm } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import { QueryTypes } from 'sequelize';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { getSequelize, initializeModels } from '../../src/models/index.js';
import { verifyAuthEventChain } from '../../src/services/auditIntegrity.js';
import { runAuditRetention } from '../../src/services/auditRetention.js';

type AuthEventModel = Awaited<ReturnType<typeof initializeModels>>['AuthEvent'];

let AuthEvent: AuthEventModel;

async function insertEvents(count: number) {
  return Promise.all(
    Array.from({ length: count }, (_, index) =>
      AuthEvent.create({ type: 'login_success', metadata: { index } }),
    ),
  );
}

async function rowsFor(ids: string[]) {
  return getSequelize().query<{ id: string; seq: string; prev_hash: string; hash: string }>(
    'SELECT id, seq, prev_hash, hash FROM auth_events WHERE id IN (:ids) ORDER BY seq',
    { replacements: { ids }, type: QueryTypes.SELECT },
  );
}

beforeAll(async () => {
  ({ AuthEvent } = await initializeModels());
});

afterAll(async () => {
  await getSequelize().close();
});

describe('auth_events hash chain', () => {
  it('links concurrent inserts into one unbroken chain', async () => {
    const events = await insertEvents(20);
    const rows = await rowsFor(events.map((event) => event.id));

    expect(rows).toHaveLength(20);
    rows.slice(1).forEach((row, index) => {
      expect(Number(row.seq)).toBe(Number(rows[index].seq) + 1);
      expect(row.prev_hash).toBe(rows[index].hash);
    });

    const report = await verifyAuthEventChain();

    expect(report.verified).toBe(true);
    expect(report.head).toEqual({ seq: Number(rows[19].seq), hash: rows[19].hash });
  });

  it.each([
    ['UPDATE', "UPDATE auth_events SET type = 'tampered'"],
    ['DELETE', 'DELETE FROM auth_events'],
    ['TRUNCATE', 'TRUNCATE auth_events'],
  ])('refuses %s', async (_op, sql) => {
    await insertEvents(1);

    await expect(getSequelize().query(sql)).rejects.toThrow(/append-only/);
  });

  it('reports a row whose content changed, and verifies again once it is restored', async () => {
    const [event] = await insertEvents(1);
    const [row] = await rowsFor([event.id]);
    const sequelize = getSequelize();

    await sequelize.query('ALTER TABLE auth_events DISABLE TRIGGER auth_events_append_only');
    try {
      await sequelize.query(`UPDATE auth_events SET metadata = '{"index":99}' WHERE id = :id`, {
        replacements: { id: event.id },
      });

      expect((await verifyAuthEventChain()).firstFailure).toEqual({
        seq: Number(row.seq),
        id: event.id,
        reason: 'hash_mismatch',
      });

      await sequelize.query(`UPDATE auth_events SET metadata = '{"index":0}' WHERE id = :id`, {
        replacements: { id: event.id },
      });
    } finally {
      await sequelize.query('ALTER TABLE auth_events ENABLE TRIGGER auth_events_append_only');
    }

    expect((await verifyAuthEventChain()).verified).toBe(true);
  });

  it('archives a prefix of the chain on retention and what remains still verifies', async () => {
    await insertEvents(5);
    const before = await verifyAuthEventChain();
    const archiveDir = await mkdtemp(join(tmpdir(), 'audit-archive-'));

    try {
      const result = await runAuditRetention(
        { retentionDays: 1, archiveDir },
        new Date(Date.now() + 10 * 24 * 60 * 60 * 1000),
      );

      expect(result).toMatchObject({ status: 'done', archived: before.rowsChecked - 1 });

      const after = await verifyAuthEventChain();
      const lines = (await readFile((result as { files: string[] }).files[0], 'utf8'))
        .trim()
        .split('\n');
      const lastArchived = JSON.parse(lines[lines.length - 2]);

      expect(after).toMatchObject({ verified: true, rowsChecked: 1, lastSeq: before.lastSeq });
      expect(after.anchorHash).toBe(lastArchived.hash);

      await insertEvents(1);

      expect(await verifyAuthEventChain()).toMatchObject({ verified: true, rowsChecked: 2 });
    } finally {
      await rm(archiveDir, { recursive: true, force: true });
    }
  });
});
