import { createHash } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { createServer, type Server } from 'node:http';
import {
  type AddressInfo,
  createServer as createTcpServer,
  type Server as TcpServer,
} from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

// The syslog transport stays tested end to end while the API refuses new syslog sinks (#586).
vi.mock('../../src/lib/auditSinkTransport.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../src/lib/auditSinkTransport.js')>()),
  SYSLOG_SINKS_AVAILABLE: true,
}));

import { AuditSink } from '../../src/models/auditSinks.js';
import { getSequelize, initializeModels } from '../../src/models/index.js';
import { runAuditRetention } from '../../src/services/auditRetention.js';
import { createSink, deliverSink } from '../../src/services/auditSinkService.js';
import { AuthEventService } from '../../src/services/authEventService.js';

let http: Server;
let httpPort: number;
let tcp: TcpServer;
let tcpPort: number;
let otlpLines: string[] = [];
let syslogStreams: string[] = [];
let answer = 200;

beforeAll(async () => {
  await initializeModels();

  http = createServer((req, res) => {
    let body = '';
    req.on('data', (chunk) => (body += chunk));
    req.on('end', () => {
      if (answer === 200) {
        for (const record of JSON.parse(body).resourceLogs[0].scopeLogs[0].logRecords) {
          otlpLines.push(record.body.stringValue);
        }
      }
      res.statusCode = answer;
      res.end();
    });
  });
  await new Promise<void>((done) => http.listen(0, '127.0.0.1', done));
  httpPort = (http.address() as AddressInfo).port;

  tcp = createTcpServer((socket) => {
    let stream = '';
    socket.setEncoding('utf8');
    socket.on('data', (chunk: string) => (stream += chunk));
    socket.on('end', () => {
      syslogStreams.push(stream);
      socket.end();
    });
  });
  await new Promise<void>((done) => tcp.listen(0, '127.0.0.1', done));
  tcpPort = (tcp.address() as AddressInfo).port;
});

beforeEach(async () => {
  otlpLines = [];
  syslogStreams = [];
  answer = 200;
  await getSequelize().query('DELETE FROM audit_sinks;');
});

afterAll(async () => {
  // A sink left behind would hold retention back in the specs that follow.
  await getSequelize().query('DELETE FROM audit_sinks;');
  http.closeAllConnections();
  await new Promise<void>((done) => http.close(() => done()));
  await new Promise<void>((done) => tcp.close(() => done()));
  await getSequelize().close();
});

async function logEvents(count: number) {
  for (let i = 0; i < count; i += 1) {
    await AuthEventService.logContext({
      type: 'login_success' as never,
      userId: '11111111-1111-4111-8111-111111111111',
      userAgent: i === 0 ? 'Mozilla/5.0 (Ünïcødé)' : 'curl/8',
      metadata: { i },
    });
  }
}

function verifyRun(lines: string[]) {
  const events = lines.map((line) => JSON.parse(line));
  for (let i = 0; i < events.length; i += 1) {
    const { prevHash, payload, hash, seq } = events[i];
    expect(
      createHash('sha256')
        .update(`${prevHash ?? ''}${payload}`, 'utf8')
        .digest('hex'),
    ).toBe(hash);
    if (i > 0) {
      expect(prevHash).toBe(events[i - 1].hash);
      expect(seq).toBe(events[i - 1].seq + 1);
    }
  }
  return events;
}

function messagesFrom(stream: string) {
  const bytes = Buffer.from(stream, 'utf8');
  const messages: string[] = [];
  let offset = 0;
  while (offset < bytes.length) {
    const space = bytes.indexOf(0x20, offset);
    const length = Number(bytes.subarray(offset, space).toString('ascii'));
    messages.push(bytes.subarray(space + 1, space + 1 + length).toString('utf8'));
    offset = space + 1 + length;
  }
  return messages;
}

describe('audit sinks against the chain', () => {
  it('streams new events to an OTLP collector in order, and the chain verifies', async () => {
    await logEvents(2);
    const sink = await createSink(
      {
        name: 'collector',
        enabled: true,
        settings: {
          kind: 'otlp',
          endpoint: `http://127.0.0.1:${httpPort}`,
          headersFromEnv: {},
          serviceName: 'seamless-auth',
        },
      },
      null,
    );
    const start = Number(sink.cursorSeq);

    // History before the sink existed is not sent.
    expect(await deliverSink(sink.id)).toBe(0);

    await logEvents(3);
    answer = 503;
    expect(await deliverSink(sink.id)).toBe(0);
    await sink.reload();
    expect(Number(sink.cursorSeq)).toBe(start);
    expect(sink.lastFailure).toBe('http_status');

    answer = 200;
    await sink.update({ nextAttemptAt: null });
    expect(await deliverSink(sink.id)).toBe(3);

    const events = verifyRun(otlpLines);
    expect(events.map((event) => event.seq)).toEqual([start + 1, start + 2, start + 3]);

    await sink.reload();
    expect(Number(sink.cursorSeq)).toBe(start + 3);
    expect(sink).toMatchObject({ failureCount: 0, nextAttemptAt: null });
    expect(sink.lastDeliveredAt).toBeInstanceOf(Date);
    expect(await deliverSink(sink.id)).toBe(0);
  });

  it('replays from startAfterSeq to a syslog collector', async () => {
    await logEvents(3);
    const [{ head }] = await getSequelize().query<{ head: string }>(
      'SELECT seq AS head FROM auth_event_chain_head WHERE id = 1',
      { type: 'SELECT' as never },
    );
    const sink = await createSink(
      {
        name: 'syslog',
        enabled: true,
        startAfterSeq: Number(head) - 3,
        settings: {
          kind: 'syslog',
          host: '127.0.0.1',
          port: tcpPort,
          transport: 'tcp',
          appName: 'seamless-auth',
          facility: 10,
        },
      },
      null,
    );

    expect(await deliverSink(sink.id)).toBe(3);

    const messages = messagesFrom(syslogStreams[0]);
    const lines = messages.map((message) => message.slice(message.indexOf('] ') + 2));
    const events = verifyRun(lines);
    expect(events.map((event) => event.seq)).toEqual([
      Number(head) - 2,
      Number(head) - 1,
      Number(head),
    ]);
    expect(messages[0]).toContain(`seq="${Number(head) - 2}" hash="${events[0].hash}"`);

    await sink.reload();
    expect(Number(sink.cursorSeq)).toBe(Number(head));
  });

  it('holds back a second replica while one sends', async () => {
    await logEvents(1);
    const sink = await createSink(
      {
        name: 'collector',
        enabled: true,
        settings: {
          kind: 'otlp',
          endpoint: `http://127.0.0.1:${httpPort}`,
          headersFromEnv: {},
          serviceName: 'seamless-auth',
        },
      },
      null,
    );
    await logEvents(1);

    const sequelize = getSequelize();
    await sequelize.transaction(async (transaction) => {
      await sequelize.query('SELECT pg_advisory_xact_lock(72641003, hashtext(:id))', {
        replacements: { id: sink.id },
        transaction,
      });
      expect(await deliverSink(sink.id)).toBe(0);
    });

    expect(await AuditSink.count()).toBe(1);
    expect(otlpLines).toHaveLength(0);
  });

  it('keeps retention from deleting what a disabled sink has yet to send', async () => {
    await logEvents(4);
    const sink = await createSink(
      {
        name: 'behind',
        enabled: false,
        settings: {
          kind: 'otlp',
          endpoint: `http://127.0.0.1:${httpPort}`,
          headersFromEnv: {},
          serviceName: 'seamless-auth',
        },
      },
      null,
    );
    const cursor = Number(sink.cursorSeq) - 2;
    await sink.update({ cursorSeq: String(cursor) });
    await logEvents(1);
    const archiveDir = await mkdtemp(join(tmpdir(), 'audit-archive-'));

    try {
      await runAuditRetention(
        { retentionDays: 1, archiveDir },
        new Date(Date.now() + 10 * 24 * 60 * 60 * 1000),
      );

      const [{ oldest }] = await getSequelize().query<{ oldest: string }>(
        'SELECT min(seq) AS oldest FROM auth_events',
        { type: 'SELECT' as never },
      );
      expect(Number(oldest)).toBe(cursor + 1);
    } finally {
      await rm(archiveDir, { recursive: true, force: true });
    }

    await sink.update({ enabled: true });
    expect(await deliverSink(sink.id)).toBe(3);
    expect(verifyRun(otlpLines).map((event) => event.seq)).toEqual([
      cursor + 1,
      cursor + 2,
      cursor + 3,
    ]);
  });
});
