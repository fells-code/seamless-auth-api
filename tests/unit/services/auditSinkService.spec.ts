import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const { query, transaction, gate } = vi.hoisted(() => {
  const query = vi.fn();
  const transaction = vi.fn(async (fn: (t: unknown) => unknown) => fn({ id: 'tx' }));
  return { query, transaction, gate: { syslog: false } };
});

vi.mock('../../../src/lib/auditSinkTransport.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/lib/auditSinkTransport.js')>();
  return {
    ...actual,
    get SYSLOG_SINKS_AVAILABLE() {
      return gate.syslog;
    },
  };
});

vi.mock('../../../src/models/index.js', () => ({
  getSequelize: () => ({ query, transaction }),
}));

vi.mock('../../../src/services/auditExport.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/services/auditExport.js')>();
  return { ...actual, readExportBatch: vi.fn() };
});

import { AuditSink } from '../../../src/models/auditSinks.js';
import {
  AuditSinkError,
  backoffMs,
  chainHead,
  createSink,
  deleteSink,
  deliverSink,
  getSink,
  listSinks,
  runAuditSinkTick,
  SINK_BATCH,
  sendSinkTest,
  serializeSink,
  startAuditSinkDelivery,
  updateSink,
} from '../../../src/services/auditSinkService.js';
import { exportLine, readExportBatch } from '../../../src/services/auditExport.js';

const at = new Date('2026-11-07T12:00:00.000Z');

let server: Server;
let port: number;
let bodies: string[];
let status: number;

beforeEach(async () => {
  gate.syslog = false;
  bodies = [];
  status = 200;
  transaction.mockImplementation(async (fn: (t: unknown) => unknown) => fn({ id: 'tx' }));
  server = createServer((req, res) => {
    let body = '';
    req.on('data', (chunk) => (body += chunk));
    req.on('end', () => {
      bodies.push(body);
      res.statusCode = status;
      res.end();
    });
  });
  await new Promise<void>((done) => server.listen(0, '127.0.0.1', done));
  port = (server.address() as AddressInfo).port;
});

afterEach(async () => {
  vi.useRealTimers();
  server.closeAllConnections();
  await new Promise<void>((done) => server.close(() => done()));
});

function settings() {
  return {
    kind: 'otlp' as const,
    endpoint: `http://127.0.0.1:${port}`,
    headersFromEnv: {},
    serviceName: 'seamless-auth',
  };
}

function sink(overrides: Record<string, unknown> = {}) {
  const record: any = {
    id: 'sink-1',
    name: 'SIEM',
    kind: 'otlp',
    enabled: true,
    settings: settings(),
    cursorSeq: '10',
    failureCount: 0,
    nextAttemptAt: null,
    lastDeliveredAt: null,
    lastFailure: null,
    lastFailureAt: null,
    createdBy: null,
    createdAt: at,
    updatedAt: at,
    ...overrides,
  };
  record.update = vi.fn(async (changes: Record<string, unknown>) => Object.assign(record, changes));
  record.destroy = vi.fn();
  return record;
}

function event(seq: number) {
  return {
    seq,
    id: `id-${seq}`,
    createdAt: at.toISOString(),
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
    prevHash: null,
    hash: 'a'.repeat(64),
    payload: `[${seq}]`,
  };
}

function bounds(head: string | null, oldest: string | null) {
  query.mockImplementation(async (sql: string) =>
    sql.includes('pg_try_advisory_xact_lock') ? [{ locked: true }] : [{ head, oldest }],
  );
}

function sentLines() {
  return bodies.flatMap((body) =>
    JSON.parse(body).resourceLogs[0].scopeLogs[0].logRecords.map(
      (record: { body: { stringValue: string } }) => record.body.stringValue,
    ),
  );
}

describe('sinks', () => {
  it('starts a new sink after the newest event', async () => {
    bounds('42', '1');
    vi.mocked(AuditSink.create).mockImplementation(async (values: any) => sink(values));

    const created = await createSink(
      { name: 'SIEM', settings: settings(), enabled: true },
      'admin-1',
    );

    expect(vi.mocked(AuditSink.create).mock.calls[0][0]).toMatchObject({
      kind: 'otlp',
      cursorSeq: '42',
      enabled: true,
      createdBy: 'admin-1',
    });
    expect(created.cursorSeq).toBe('42');
  });

  it('replays from startAfterSeq, but not from before what retention kept or past the head', async () => {
    bounds('42', '20');
    vi.mocked(AuditSink.create).mockImplementation(async (values: any) => sink(values));

    await createSink(
      { name: 'SIEM', settings: settings(), enabled: true, startAfterSeq: 19 },
      null,
    );
    expect(vi.mocked(AuditSink.create).mock.calls[0][0]).toMatchObject({ cursorSeq: '19' });

    await expect(
      createSink({ name: 'SIEM', settings: settings(), enabled: true, startAfterSeq: 18 }, null),
    ).rejects.toMatchObject({ status: 400, message: expect.stringContaining('retention') });
    await expect(
      createSink({ name: 'SIEM', settings: settings(), enabled: true, startAfterSeq: 43 }, null),
    ).rejects.toMatchObject({ status: 400 });
  });

  it('treats an empty chain as starting at zero', async () => {
    query.mockResolvedValue([{ head: null, oldest: null }]);
    vi.mocked(AuditSink.create).mockImplementation(async (values: any) => sink(values));

    await createSink({ name: 'SIEM', settings: settings(), startAfterSeq: 0 } as never, null);

    expect(vi.mocked(AuditSink.create).mock.calls[0][0]).toMatchObject({
      cursorSeq: '0',
      enabled: true,
    });
    expect(await chainHead()).toBe(0);
  });

  it('refuses a destination no callout may reach', async () => {
    await expect(
      createSink(
        { name: 'SIEM', settings: { ...settings(), endpoint: 'http://169.254.169.254' } },
        null,
      ),
    ).rejects.toBeInstanceOf(AuditSinkError);
    expect(AuditSink.create).not.toHaveBeenCalled();
  });

  it('lists, reads and deletes, and answers 404 for a missing sink', async () => {
    const record = sink();
    vi.mocked(AuditSink.findAll).mockResolvedValue([record]);
    vi.mocked(AuditSink.findByPk).mockResolvedValueOnce(record).mockResolvedValueOnce(record);

    expect(await listSinks()).toEqual([record]);
    expect(await getSink('sink-1')).toBe(record);
    expect(await deleteSink('sink-1')).toBe(record);
    expect(record.destroy).toHaveBeenCalled();

    vi.mocked(AuditSink.findByPk).mockResolvedValue(null);
    await expect(getSink('missing')).rejects.toMatchObject({ status: 404 });
  });

  it('updates fields and clears the backoff, keeping the cursor', async () => {
    gate.syslog = true;
    const record = sink({ failureCount: 4, nextAttemptAt: new Date(Date.now() + 60_000) });
    vi.mocked(AuditSink.findByPk).mockResolvedValue(record);

    await updateSink('sink-1', { name: 'Renamed' });
    await updateSink('sink-1', {
      settings: {
        kind: 'syslog',
        host: 'collector.example.com',
        port: 6514,
        transport: 'tls',
        appName: 'seamless-auth',
        facility: 10,
      },
      enabled: false,
    });

    expect(record).toMatchObject({
      name: 'Renamed',
      kind: 'syslog',
      enabled: false,
      cursorSeq: '10',
      failureCount: 0,
      nextAttemptAt: null,
    });
  });

  it('refuses an update to an unreachable destination', async () => {
    vi.mocked(AuditSink.findByPk).mockResolvedValue(sink());

    await expect(
      updateSink('sink-1', { settings: { ...settings(), endpoint: 'http://[fe80::1]/' } }),
    ).rejects.toMatchObject({ status: 400 });
  });

  it('reports lag against the chain head', () => {
    const serialized = serializeSink(
      sink({ lastDeliveredAt: at, lastFailure: 'timed_out', lastFailureAt: at }),
      15,
    );

    expect(serialized.status).toEqual({
      cursorSeq: 10,
      lagEvents: 5,
      lastDeliveredAt: at.toISOString(),
      lastFailure: 'timed_out',
      lastFailureAt: at.toISOString(),
    });
    expect(serializeSink(sink({ cursorSeq: '20' }), 15).status).toMatchObject({
      lagEvents: 0,
      lastDeliveredAt: null,
      lastFailure: null,
      lastFailureAt: null,
    });
  });
});

describe('the test record', () => {
  it('is sent once, outside the chain, and moves nothing', async () => {
    const record = sink();
    vi.mocked(AuditSink.findByPk).mockResolvedValue(record);

    const result = await sendSinkTest('sink-1');

    expect(result).toMatchObject({ ok: true, failure: null, statusCode: 200 });
    const [line] = sentLines();
    expect(JSON.parse(line)).toMatchObject({ type: 'test', test: true, sinkId: 'sink-1' });
    expect(record.update).not.toHaveBeenCalled();
    expect(record.cursorSeq).toBe('10');
  });

  it('reports a failure without recording it on the sink', async () => {
    status = 500;
    const record = sink();
    vi.mocked(AuditSink.findByPk).mockResolvedValue(record);

    expect(await sendSinkTest('sink-1')).toMatchObject({ ok: false, failure: 'http_status' });
    expect(record.update).not.toHaveBeenCalled();
  });
});

describe('delivery', () => {
  function locked(value: boolean) {
    query.mockResolvedValue([{ locked: value }]);
  }

  it('sends the events past the cursor in order and advances the cursor on success', async () => {
    locked(true);
    const record = sink();
    vi.mocked(AuditSink.findByPk).mockResolvedValue(record);
    vi.mocked(readExportBatch).mockResolvedValue([event(11), event(12), event(13)]);

    expect(await deliverSink('sink-1')).toBe(3);

    expect(readExportBatch).toHaveBeenCalledWith(
      expect.objectContaining({ afterSeq: 10, limit: SINK_BATCH, transaction: { id: 'tx' } }),
    );
    expect(sentLines()).toEqual([event(11), event(12), event(13)].map(exportLine));
    expect(record).toMatchObject({ cursorSeq: '13', failureCount: 0, nextAttemptAt: null });
    expect(record.lastDeliveredAt).toBeInstanceOf(Date);
    expect(query).toHaveBeenCalledWith(
      expect.stringContaining('pg_try_advisory_xact_lock(:lockClass, hashtext(:id))'),
      expect.objectContaining({ replacements: expect.objectContaining({ id: 'sink-1' }) }),
    );
  });

  it('does not advance the cursor on failure and backs off', async () => {
    locked(true);
    status = 503;
    const record = sink({ failureCount: 2 });
    vi.mocked(AuditSink.findByPk).mockResolvedValue(record);
    vi.mocked(readExportBatch).mockResolvedValue([event(11)]);

    expect(await deliverSink('sink-1')).toBe(0);

    expect(bodies).toHaveLength(1);
    expect(record.cursorSeq).toBe('10');
    expect(record).toMatchObject({ lastFailure: 'http_status', failureCount: 3 });
    expect(record.lastFailureAt).toBeInstanceOf(Date);
    expect(record.nextAttemptAt.getTime()).toBeGreaterThan(Date.now());
  });

  it('resends the same batch after a failure, so nothing is skipped', async () => {
    locked(true);
    const record = sink();
    vi.mocked(AuditSink.findByPk).mockResolvedValue(record);
    vi.mocked(readExportBatch).mockImplementation(async ({ afterSeq }) =>
      [event(11), event(12)].filter((entry) => entry.seq > afterSeq),
    );

    status = 500;
    await deliverSink('sink-1');
    record.nextAttemptAt = null;
    status = 200;
    await deliverSink('sink-1');

    expect(sentLines()).toEqual([event(11), event(12), event(11), event(12)].map(exportLine));
    expect(record.cursorSeq).toBe('12');
  });

  it('stands down when another replica holds the sink', async () => {
    locked(false);

    expect(await deliverSink('sink-1')).toBe(0);
    expect(AuditSink.findByPk).not.toHaveBeenCalled();
  });

  it('skips a sink that is gone, disabled, backing off or caught up', async () => {
    locked(true);
    vi.mocked(readExportBatch).mockResolvedValue([]);

    for (const found of [
      null,
      sink({ enabled: false }),
      sink({ nextAttemptAt: new Date(Date.now() + 30_000) }),
      sink(),
    ]) {
      vi.mocked(AuditSink.findByPk).mockResolvedValueOnce(found);
      expect(await deliverSink('sink-1')).toBe(0);
    }
    expect(readExportBatch).toHaveBeenCalledTimes(1);
    expect(bodies).toHaveLength(0);
  });

  it('backs off exponentially to a minute', () => {
    vi.spyOn(Math, 'random').mockReturnValue(0);
    expect([1, 2, 3, 7, 8, 50].map(backoffMs)).toEqual([1000, 2000, 4000, 60_000, 60_000, 60_000]);
    vi.spyOn(Math, 'random').mockReturnValue(0.99);
    expect(backoffMs(20)).toBeLessThanOrEqual(60_000);
    expect(backoffMs(20)).toBeGreaterThan(53_000);
  });
});

describe('the loop', () => {
  it('drains each due sink until a short batch', async () => {
    vi.mocked(AuditSink.findAll).mockResolvedValue([{ id: 'sink-1' }] as never);
    query.mockResolvedValue([{ locked: true }]);
    const record = sink();
    vi.mocked(AuditSink.findByPk).mockResolvedValue(record);
    const full = Array.from({ length: SINK_BATCH }, (_, index) => event(11 + index));
    vi.mocked(readExportBatch)
      .mockResolvedValueOnce(full)
      .mockResolvedValueOnce([event(111)]);

    await runAuditSinkTick();

    expect(readExportBatch).toHaveBeenCalledTimes(2);
    expect(record.cursorSeq).toBe('111');
  });

  it('caps one sink at fifty batches a tick', async () => {
    vi.mocked(AuditSink.findAll).mockResolvedValue([{ id: 'sink-1' }] as never);
    query.mockResolvedValue([{ locked: true }]);
    vi.mocked(AuditSink.findByPk).mockResolvedValue(sink());
    vi.mocked(readExportBatch).mockImplementation(async ({ afterSeq }) =>
      Array.from({ length: SINK_BATCH }, (_, index) => event(afterSeq + 1 + index)),
    );

    await runAuditSinkTick();

    expect(readExportBatch).toHaveBeenCalledTimes(50);
  });

  it('logs rather than throws when a sink or the tick fails', async () => {
    vi.mocked(AuditSink.findAll).mockResolvedValueOnce([{ id: 'sink-1' }] as never);
    transaction.mockRejectedValueOnce(new Error('database unavailable'));
    await expect(runAuditSinkTick()).resolves.toBeUndefined();

    vi.mocked(AuditSink.findAll).mockRejectedValueOnce(new Error('database unavailable'));
    await expect(runAuditSinkTick()).resolves.toBeUndefined();
  });

  it('ticks once a second and never overlaps', async () => {
    vi.useFakeTimers();
    let release: () => void = () => {};
    vi.mocked(AuditSink.findAll).mockImplementation(
      () => new Promise((done) => (release = () => done([]))) as never,
    );

    const timer = startAuditSinkDelivery();
    await vi.advanceTimersByTimeAsync(3000);
    expect(AuditSink.findAll).toHaveBeenCalledTimes(1);

    release();
    await vi.advanceTimersByTimeAsync(1000);
    expect(AuditSink.findAll).toHaveBeenCalledTimes(2);
    clearInterval(timer);
  });
});
