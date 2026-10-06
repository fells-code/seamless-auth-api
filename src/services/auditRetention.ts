/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { createHash } from 'crypto';
import { mkdir, open, rename } from 'fs/promises';
import { join } from 'path';
import { QueryTypes, Sequelize } from 'sequelize';

import { resolveSslOptions, withoutSslMode } from '../config/database.cjs';
import { getSequelize } from '../models/index.js';
import getLogger from '../utils/logger.js';
import { buildManifest, ExportedAuthEvent, readExportBatch } from './auditExport.js';

const logger = getLogger('audit-retention');

const DAY_MS = 24 * 60 * 60 * 1000;
const ARCHIVE_BATCH_SIZE = 10_000;
// Arbitrary but fixed, so every replica contends for the same lock.
const RETENTION_LOCK_KEY = 717_301_173;

export interface AuditRetentionSettings {
  retentionDays: number | null;
  archiveDir: string | null;
}

export type AuditRetentionResult =
  | { status: 'disabled' }
  | { status: 'no_archive_dir' }
  | { status: 'busy' }
  | { status: 'done'; archived: number; files: string[]; cutoff: string };

/**
 * `AUDIT_RETENTION_DAYS` unset means keep everything, which is what every deployment did
 * before the setting existed. A value that does not parse to a positive whole number is
 * treated the same way and reported, so a typo never deletes anything.
 */
export function readAuditRetentionSettings(env = process.env): AuditRetentionSettings {
  const rawDays = env.AUDIT_RETENTION_DAYS?.trim();
  let retentionDays: number | null = null;

  if (rawDays) {
    const parsed = Number(rawDays);
    if (Number.isInteger(parsed) && parsed > 0) {
      retentionDays = parsed;
    } else {
      logger.error(
        `AUDIT_RETENTION_DAYS=${rawDays} is not a positive whole number; audit events will not expire`,
      );
    }
  }

  return { retentionDays, archiveDir: env.AUDIT_ARCHIVE_DIR?.trim() || null };
}

let retentionSequelize: Sequelize | null = null;

/**
 * The connection retention deletes through. `AUDIT_RETENTION_DATABASE_URL` lets it run as
 * a role that holds DELETE on auth_events, so the application role does not have to.
 */
function getRetentionSequelize(env = process.env): Sequelize {
  const url = env.AUDIT_RETENTION_DATABASE_URL;

  if (!url) return getSequelize();
  if (retentionSequelize) return retentionSequelize;

  const ssl = resolveSslOptions(url);
  retentionSequelize = new Sequelize(withoutSslMode(url), {
    logging: false,
    ...(ssl ? { dialectOptions: { ssl } } : {}),
  });

  return retentionSequelize;
}

async function writeArchiveFile(archiveDir: string, events: ExportedAuthEvent[]) {
  const first = events[0];
  const last = events[events.length - 1];
  const name = `auth-events-${String(first.seq).padStart(12, '0')}-${String(last.seq).padStart(12, '0')}.ndjson`;
  const path = join(archiveDir, name);
  const partial = `${path}.partial`;

  const manifest = buildManifest({
    reason: 'retention',
    firstSeq: first.seq,
    lastSeq: last.seq,
    count: events.length,
    anchorHash: first.prevHash,
    lastHash: last.hash,
  });

  const body =
    events.map((event) => JSON.stringify(event)).join('\n') + `\n${JSON.stringify(manifest)}\n`;

  // Written under a temporary name, flushed to disk, then renamed, so a file under its
  // final name is always complete. The rows are only deleted after this returns.
  const handle = await open(partial, 'w');
  try {
    await handle.writeFile(body, 'utf8');
    await handle.sync();
  } finally {
    await handle.close();
  }
  await rename(partial, path);

  const digest = createHash('sha256').update(body, 'utf8').digest('hex');
  const checksum = await open(`${path}.sha256`, 'w');
  try {
    await checksum.writeFile(`${digest}  ${name}\n`, 'utf8');
    await checksum.sync();
  } finally {
    await checksum.close();
  }

  return path;
}

/**
 * Archives and then deletes audit events older than the retention period.
 *
 * Only a contiguous run from the start of the chain is ever removed: up to, not
 * including, the first event that is still inside the period, and never the newest
 * event, whose hash the chain head points at. What remains therefore always verifies,
 * starting from the archive's last hash. Every batch is archived to disk before its rows
 * are deleted, in a transaction that is the only place `seamless.audit_retention` is
 * turned on. Without an archive directory nothing is deleted at all.
 */
export async function runAuditRetention(
  settings: AuditRetentionSettings = readAuditRetentionSettings(),
  now = new Date(),
): Promise<AuditRetentionResult> {
  const { retentionDays, archiveDir } = settings;

  if (!retentionDays) return { status: 'disabled' };

  if (!archiveDir) {
    logger.error(
      'AUDIT_RETENTION_DAYS is set without AUDIT_ARCHIVE_DIR; audit events are not deleted without an archive',
    );
    return { status: 'no_archive_dir' };
  }

  await mkdir(archiveDir, { recursive: true });

  const cutoff = new Date(now.getTime() - retentionDays * DAY_MS);
  const sequelize = getRetentionSequelize();
  const files: string[] = [];
  let archived = 0;

  for (;;) {
    const outcome = await sequelize.transaction(async (transaction) => {
      const [{ locked }] = await sequelize.query<{ locked: boolean }>(
        'SELECT pg_try_advisory_xact_lock(:key) AS locked',
        { type: QueryTypes.SELECT, replacements: { key: RETENTION_LOCK_KEY }, transaction },
      );

      if (!locked) return 'busy' as const;

      await sequelize.query("SET LOCAL seamless.audit_retention = 'on'", { transaction });

      const [{ max_seq: maxSeq }] = await sequelize.query<{ max_seq: string | null }>(
        `SELECT LEAST(
            (SELECT min(seq) FROM public.auth_events WHERE created_at >= :cutoff),
            (SELECT max(seq) FROM public.auth_events)
          ) - 1 AS max_seq`,
        {
          type: QueryTypes.SELECT,
          replacements: { cutoff: cutoff.toISOString() },
          transaction,
        },
      );

      if (maxSeq === null || Number(maxSeq) < 1) return 'finished' as const;

      const batch = await readExportBatch({
        afterSeq: 0,
        maxSeq: Number(maxSeq),
        limit: ARCHIVE_BATCH_SIZE,
        sequelize,
        transaction,
      });

      if (batch.length === 0) return 'finished' as const;

      const path = await writeArchiveFile(archiveDir, batch);

      await sequelize.query('DELETE FROM public.auth_events WHERE seq <= :lastSeq', {
        replacements: { lastSeq: batch[batch.length - 1].seq },
        transaction,
      });

      files.push(path);
      archived += batch.length;

      return batch.length < ARCHIVE_BATCH_SIZE ? ('finished' as const) : ('more' as const);
    });

    if (outcome === 'busy') {
      return archived
        ? { status: 'done', archived, files, cutoff: cutoff.toISOString() }
        : { status: 'busy' };
    }

    if (outcome === 'finished') break;
  }

  if (archived) {
    logger.info(`Archived and removed ${archived} audit events older than ${cutoff.toISOString()}`);
  }

  return { status: 'done', archived, files, cutoff: cutoff.toISOString() };
}

/**
 * Logs the chain head, so the application logs hold an anchor outside the database. A
 * later integrity check whose chain does not pass through a logged head shows the trail
 * was rewritten, which the chain alone cannot show to someone who owns the table.
 */
export async function logAuditChainCheckpoint() {
  const [head] = await getSequelize().query<{ seq: string; last_hash: string | null }>(
    'SELECT seq, last_hash FROM public.auth_event_chain_head WHERE id = 1',
    { type: QueryTypes.SELECT },
  );

  if (head) {
    logger.info(`Audit chain checkpoint seq=${head.seq} hash=${head.last_hash ?? 'none'}`);
  }
}

const MAINTENANCE_INTERVAL_MS = DAY_MS;
const FIRST_RUN_DELAY_MS = 60 * 1000;

async function runAuditMaintenance() {
  try {
    await logAuditChainCheckpoint();
    await runAuditRetention();
  } catch (error) {
    logger.error(`Audit maintenance failed: ${error}`);
  }
}

/** Daily checkpoint and retention, starting a minute after boot. */
export function startAuditMaintenance() {
  const first = setTimeout(() => {
    void runAuditMaintenance();
    setInterval(() => void runAuditMaintenance(), MAINTENANCE_INTERVAL_MS).unref();
  }, FIRST_RUN_DELAY_MS);
  first.unref();
}
