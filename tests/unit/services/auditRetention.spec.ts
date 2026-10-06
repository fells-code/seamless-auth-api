import { mkdir, mkdtemp, readdir, readFile, rm } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { getSequelize } from '../../../src/models/index.js';
import { readExportBatch } from '../../../src/services/auditExport.js';
import {
  logAuditChainCheckpoint,
  readAuditRetentionSettings,
  runAuditRetention,
  startAuditMaintenance,
} from '../../../src/services/auditRetention.js';

vi.mock('../../../src/models/index.js', () => ({
  getSequelize: vi.fn(),
}));

const { retentionQuery, retentionTransaction, SequelizeMock } = vi.hoisted(() => {
  const retentionQuery = vi.fn();
  const retentionTransaction = vi.fn(async (fn: (t: unknown) => unknown) => fn({ id: 'rtx' }));
  const SequelizeMock = vi.fn(function Sequelize() {
    return { query: retentionQuery, transaction: retentionTransaction };
  });
  return { retentionQuery, retentionTransaction, SequelizeMock };
});

vi.mock('sequelize', async (importOriginal) => ({
  ...(await importOriginal<typeof import('sequelize')>()),
  Sequelize: SequelizeMock,
}));

vi.mock('../../../src/services/auditExport.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/services/auditExport.js')>()),
  readExportBatch: vi.fn(),
}));

const query = vi.fn();
const transaction = vi.fn(async (fn: (t: unknown) => unknown) => fn({ id: 'tx' }));

function event(seq: number) {
  return {
    seq,
    id: `event-${seq}`,
    createdAt: '2026-01-01T00:00:00.000Z',
    type: 'login_success',
    userId: null,
    actorUserId: null,
    sessionId: null,
    attemptId: null,
    ipAddress: null,
    userAgent: null,
    deploymentId: null,
    deviceClass: null,
    mailProvider: null,
    owner: null,
    metadata: null,
    prevHash: `prev-${seq}`,
    hash: `hash-${seq}`,
    payload: `[${seq}]`,
  };
}

let archiveDir: string;

beforeEach(async () => {
  vi.clearAllMocks();
  vi.mocked(getSequelize).mockReturnValue({ query, transaction } as never);
  archiveDir = await mkdtemp(join(tmpdir(), 'audit-archive-'));
});

afterEach(async () => {
  await rm(archiveDir, { recursive: true, force: true });
});

function respondTo(handlers: Record<string, unknown>) {
  query.mockImplementation(async (sql: string) => {
    for (const [fragment, value] of Object.entries(handlers)) {
      if (sql.includes(fragment)) return value;
    }
    return [];
  });
}

describe('readAuditRetentionSettings', () => {
  it('keeps everything unless a positive whole number of days is set', () => {
    expect(readAuditRetentionSettings({}).retentionDays).toBeNull();
    expect(readAuditRetentionSettings({ AUDIT_RETENTION_DAYS: '0' }).retentionDays).toBeNull();
    expect(readAuditRetentionSettings({ AUDIT_RETENTION_DAYS: '30d' }).retentionDays).toBeNull();
    expect(readAuditRetentionSettings({ AUDIT_RETENTION_DAYS: '2.5' }).retentionDays).toBeNull();
    expect(readAuditRetentionSettings({ AUDIT_RETENTION_DAYS: ' 365 ' }).retentionDays).toBe(365);
  });

  it('reads the archive directory', () => {
    expect(readAuditRetentionSettings({ AUDIT_ARCHIVE_DIR: '/var/audit' }).archiveDir).toBe(
      '/var/audit',
    );
    expect(readAuditRetentionSettings({ AUDIT_ARCHIVE_DIR: '  ' }).archiveDir).toBeNull();
  });
});

describe('runAuditRetention', () => {
  it('does nothing when retention is not configured', async () => {
    await expect(runAuditRetention({ retentionDays: null, archiveDir })).resolves.toEqual({
      status: 'disabled',
    });
    expect(transaction).not.toHaveBeenCalled();
  });

  it('never deletes without somewhere to archive to', async () => {
    await expect(runAuditRetention({ retentionDays: 30, archiveDir: null })).resolves.toEqual({
      status: 'no_archive_dir',
    });
    expect(transaction).not.toHaveBeenCalled();
  });

  it('stands down when another replica holds the lock', async () => {
    respondTo({ pg_try_advisory_xact_lock: [{ locked: false }] });

    await expect(runAuditRetention({ retentionDays: 30, archiveDir })).resolves.toEqual({
      status: 'busy',
    });
    expect(query).not.toHaveBeenCalledWith(expect.stringContaining('DELETE'), expect.anything());
  });

  it('archives a batch to disk, then deletes exactly that batch', async () => {
    respondTo({
      pg_try_advisory_xact_lock: [{ locked: true }],
      'AS max_seq': [{ max_seq: '3' }],
    });
    vi.mocked(readExportBatch).mockResolvedValueOnce([event(1), event(2), event(3)]);

    const result = await runAuditRetention(
      { retentionDays: 30, archiveDir },
      new Date('2026-06-01T00:00:00Z'),
    );

    expect(result).toEqual(
      expect.objectContaining({ status: 'done', archived: 3, cutoff: '2026-05-02T00:00:00.000Z' }),
    );
    expect(query).toHaveBeenCalledWith("SET LOCAL seamless.audit_retention = 'on'", {
      transaction: { id: 'tx' },
    });
    expect(query).toHaveBeenCalledWith('DELETE FROM public.auth_events WHERE seq <= :lastSeq', {
      replacements: { lastSeq: 3 },
      transaction: { id: 'tx' },
    });

    const files = (await readdir(archiveDir)).sort();
    expect(files).toEqual([
      'auth-events-000000000001-000000000003.ndjson',
      'auth-events-000000000001-000000000003.ndjson.sha256',
    ]);

    const lines = (await readFile(join(archiveDir, files[0]), 'utf8')).trim().split('\n');
    const manifest = JSON.parse(lines[lines.length - 1]);
    expect(lines).toHaveLength(4);
    expect(manifest).toEqual(
      expect.objectContaining({
        type: 'manifest',
        reason: 'retention',
        firstSeq: 1,
        lastSeq: 3,
        count: 3,
        anchorHash: 'prev-1',
        lastHash: 'hash-3',
      }),
    );
  });

  it('keeps the rows when the archive cannot be written', async () => {
    respondTo({
      pg_try_advisory_xact_lock: [{ locked: true }],
      'AS max_seq': [{ max_seq: '1' }],
    });
    vi.mocked(readExportBatch).mockResolvedValueOnce([event(1)]);
    // A directory where the temporary file has to go makes the write itself fail.
    await mkdir(join(archiveDir, 'auth-events-000000000001-000000000001.ndjson.partial'));

    await expect(runAuditRetention({ retentionDays: 30, archiveDir })).rejects.toThrow();
    expect(readExportBatch).toHaveBeenCalled();
    expect(query).not.toHaveBeenCalledWith(expect.stringContaining('DELETE'), expect.anything());
  });

  it('stops when nothing is past the cutoff', async () => {
    respondTo({
      pg_try_advisory_xact_lock: [{ locked: true }],
      'AS max_seq': [{ max_seq: null }],
    });

    await expect(runAuditRetention({ retentionDays: 30, archiveDir })).resolves.toEqual(
      expect.objectContaining({ status: 'done', archived: 0 }),
    );
    expect(readExportBatch).not.toHaveBeenCalled();
  });
});

describe('runAuditRetention across batches', () => {
  it('keeps going while batches come back full', async () => {
    respondTo({
      pg_try_advisory_xact_lock: [{ locked: true }],
      'AS max_seq': [{ max_seq: '20000' }],
    });
    const full = Array.from({ length: 10_000 }, (_, i) => event(i + 1));
    const rest = [event(10_001)];
    vi.mocked(readExportBatch).mockResolvedValueOnce(full).mockResolvedValueOnce(rest);

    const result = await runAuditRetention({ retentionDays: 30, archiveDir });

    expect(result).toEqual(expect.objectContaining({ status: 'done', archived: 10_001 }));
    expect(transaction).toHaveBeenCalledTimes(2);
  });

  it('reports what it archived when another replica takes over partway', async () => {
    let calls = 0;
    query.mockImplementation(async (sql: string) => {
      if (sql.includes('pg_try_advisory_xact_lock')) {
        calls += 1;
        return [{ locked: calls === 1 }];
      }
      if (sql.includes('AS max_seq')) return [{ max_seq: '20000' }];
      return [];
    });
    vi.mocked(readExportBatch).mockResolvedValueOnce(
      Array.from({ length: 10_000 }, (_, i) => event(i + 1)),
    );

    const result = await runAuditRetention({ retentionDays: 30, archiveDir });

    expect(result).toEqual(expect.objectContaining({ status: 'done', archived: 10_000 }));
  });

  it('stops when the batch comes back empty', async () => {
    respondTo({
      pg_try_advisory_xact_lock: [{ locked: true }],
      'AS max_seq': [{ max_seq: '5' }],
    });
    vi.mocked(readExportBatch).mockResolvedValueOnce([]);

    await expect(runAuditRetention({ retentionDays: 30, archiveDir })).resolves.toEqual(
      expect.objectContaining({ archived: 0 }),
    );
    expect(query).not.toHaveBeenCalledWith(expect.stringContaining('DELETE'), expect.anything());
  });
});

describe('separate retention connection', () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it('deletes through AUDIT_RETENTION_DATABASE_URL when it is set', async () => {
    vi.stubEnv(
      'AUDIT_RETENTION_DATABASE_URL',
      'postgres://retention:secret@db.internal:5432/seamless?sslmode=require',
    );
    retentionQuery.mockImplementation(async (sql: string) =>
      sql.includes('pg_try_advisory_xact_lock') ? [{ locked: true }] : [{ max_seq: null }],
    );

    await runAuditRetention({ retentionDays: 30, archiveDir });
    await runAuditRetention({ retentionDays: 30, archiveDir });

    expect(SequelizeMock).toHaveBeenCalledTimes(1);
    expect(SequelizeMock).toHaveBeenCalledWith(
      'postgres://retention:secret@db.internal:5432/seamless',
      expect.objectContaining({ dialectOptions: expect.anything() }),
    );
    expect(retentionTransaction).toHaveBeenCalled();
    expect(transaction).not.toHaveBeenCalled();
  });
});

describe('logAuditChainCheckpoint', () => {
  it('logs the chain head', async () => {
    query.mockResolvedValue([{ seq: '42', last_hash: 'f'.repeat(64) }]);

    await logAuditChainCheckpoint();

    expect(query).toHaveBeenCalledWith(
      expect.stringContaining('auth_event_chain_head'),
      expect.anything(),
    );
  });

  it('copes with a database that has no chain head yet', async () => {
    query.mockResolvedValue([]);

    await expect(logAuditChainCheckpoint()).resolves.toBeUndefined();
  });
});

describe('startAuditMaintenance', () => {
  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllEnvs();
  });

  it('checkpoints a minute after boot and then daily, surviving a failed run', async () => {
    vi.useFakeTimers();
    query.mockRejectedValueOnce(new Error('database unavailable'));
    query.mockResolvedValue([{ seq: '1', last_hash: null }]);

    startAuditMaintenance();
    expect(query).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(60 * 1000);
    expect(query).toHaveBeenCalledTimes(1);

    await vi.advanceTimersByTimeAsync(24 * 60 * 60 * 1000);
    expect(query).toHaveBeenCalledTimes(2);
  });
});

describe('readAuditRetentionSettings defaults', () => {
  it('reads the process environment when given nothing', () => {
    vi.stubEnv('AUDIT_RETENTION_DAYS', '90');
    expect(readAuditRetentionSettings().retentionDays).toBe(90);
    vi.unstubAllEnvs();
  });
});
