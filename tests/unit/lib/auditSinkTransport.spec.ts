import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createServer as createHttpServer, type IncomingHttpHeaders, type Server } from 'node:http';
import {
  createServer as createTcpServer,
  type AddressInfo,
  type Server as TcpServer,
} from 'node:net';
import { join } from 'node:path';
import { createServer as createTlsServer, type TLSSocket } from 'node:tls';

import type { OtlpSinkSettings, SyslogSinkSettings } from '@seamless-auth/types';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  eventRecord,
  octetFrame,
  otlpLogsBody,
  otlpLogsUrl,
  sendToSink,
  sinkDestinationProblem,
  SYSLOG_SD_ID,
  syslogMessage,
  testRecord,
} from '../../../src/lib/auditSinkTransport.js';
import { exportLine, type ExportedAuthEvent } from '../../../src/services/auditExport.js';

const fixtures = join(__dirname, '../../fixtures/auditSinkTls');
const pem = (name: string) => readFileSync(join(fixtures, name), 'utf8');

function sha256(text: string) {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

/** A run of the chain built the way the database builds it. */
function chain(count: number, firstSeq = 1, anchor: string | null = null): ExportedAuthEvent[] {
  const events: ExportedAuthEvent[] = [];
  let prevHash = anchor;
  for (let i = 0; i < count; i += 1) {
    const seq = firstSeq + i;
    const createdAt = new Date(Date.UTC(2026, 10, 7, 12, 0, i)).toISOString();
    const type = i === 1 ? 'login_suspicious' : 'login_success';
    const userAgent = i === 2 ? 'Mozilla/5.0 (Ünïcødé ✓)' : 'curl/8';
    const payload = JSON.stringify([
      seq,
      `id-${seq}`,
      'user-1',
      null,
      'session-1',
      type,
      userAgent,
    ]);
    const hash = sha256((prevHash ?? '') + payload);
    events.push({
      seq,
      id: `id-${seq}`,
      createdAt,
      type,
      userId: 'user-1',
      actorUserId: i === 0 ? 'admin-1' : null,
      sessionId: 'session-1',
      attemptId: null,
      ipAddress: '203.0.113.9',
      userAgent,
      deploymentId: null,
      deviceClass: null,
      mailProvider: null,
      owner: null,
      metadata: { method: 'passkey' },
      prevHash,
      hash,
      payload,
    });
    prevHash = hash;
  }
  return events;
}

/** What a downstream verifier does with the lines it received. */
function verifies(lines: string[], anchor: string | null = null) {
  let prev = anchor;
  for (const line of lines) {
    const event = JSON.parse(line) as ExportedAuthEvent;
    if (event.prevHash !== prev) return false;
    if (sha256((event.prevHash ?? '') + event.payload) !== event.hash) return false;
    prev = event.hash;
  }
  return true;
}

type Received = { url: string; method: string; headers: IncomingHttpHeaders; body: string };

let httpServer: Server;
let httpPort: number;
let received: Received[];
let answer: { status: number; headers?: Record<string, string> };

beforeEach(async () => {
  received = [];
  answer = { status: 200 };
  httpServer = createHttpServer((req, res) => {
    let body = '';
    req.on('data', (chunk) => (body += chunk));
    req.on('end', () => {
      received.push({ url: req.url ?? '', method: req.method ?? '', headers: req.headers, body });
      res.writeHead(answer.status, answer.headers ?? {});
      res.end('{}');
    });
  });
  await new Promise<void>((done) => httpServer.listen(0, '127.0.0.1', done));
  httpPort = (httpServer.address() as AddressInfo).port;
});

afterEach(async () => {
  httpServer.closeAllConnections();
  await new Promise<void>((done) => httpServer.close(() => done()));
});

function otlp(overrides: Partial<OtlpSinkSettings> = {}): OtlpSinkSettings {
  return {
    kind: 'otlp',
    endpoint: `http://127.0.0.1:${httpPort}/collector/`,
    headersFromEnv: {},
    serviceName: 'seamless-auth',
    ...overrides,
  };
}

function syslog(port: number, overrides: Partial<SyslogSinkSettings> = {}): SyslogSinkSettings {
  return {
    kind: 'syslog',
    host: '127.0.0.1',
    port,
    transport: 'tcp',
    appName: 'seamless-auth',
    facility: 10,
    ...overrides,
  };
}

describe('OTLP', () => {
  it('posts one log record per event to <endpoint>/v1/logs, the export line as the body', async () => {
    const events = chain(3);

    const attempt = await sendToSink(
      otlp({ serviceName: 'auth-prod' }),
      events.map(eventRecord),
      {},
    );

    expect(attempt).toMatchObject({ ok: true, statusCode: 200, failure: null });
    expect(received).toHaveLength(1);
    const [request] = received;
    expect(request.method).toBe('POST');
    expect(request.url).toBe('/collector/v1/logs');
    expect(request.headers['content-type']).toBe('application/json');

    const body = JSON.parse(request.body);
    const [resourceLogs] = body.resourceLogs;
    expect(resourceLogs.resource.attributes).toEqual([
      { key: 'service.name', value: { stringValue: 'auth-prod' } },
    ]);
    const [scopeLogs] = resourceLogs.scopeLogs;
    expect(scopeLogs.scope.name).toBe('seamless-auth.audit');

    const lines = scopeLogs.logRecords.map(
      (record: { body: { stringValue: string } }) => record.body.stringValue,
    );
    // Exactly the export's line, so the chain verifies from what the collector stored.
    expect(lines).toEqual(events.map(exportLine));
    expect(verifies(lines)).toBe(true);

    const [first, second] = scopeLogs.logRecords;
    expect(first.timeUnixNano).toBe(`${Date.parse(events[0].createdAt)}000000`);
    expect(first.severityNumber).toBe(9);
    expect(second.severityNumber).toBe(13);
    expect(second.severityText).toBe('WARN');
    const attributes = Object.fromEntries(
      first.attributes.map((entry: { key: string; value: unknown }) => [entry.key, entry.value]),
    );
    expect(attributes).toEqual({
      'seamless.audit.seq': { intValue: '1' },
      'seamless.audit.id': { stringValue: 'id-1' },
      'seamless.audit.type': { stringValue: 'login_success' },
      'seamless.audit.hash': { stringValue: events[0].hash },
      'user.id': { stringValue: 'user-1' },
      'seamless.audit.actor_user_id': { stringValue: 'admin-1' },
      'session.id': { stringValue: 'session-1' },
    });
    expect(second.attributes).toContainEqual({
      key: 'seamless.audit.prev_hash',
      value: { stringValue: events[0].hash },
    });
  });

  it('builds the logs URL without doubling slashes and keeps a query string', () => {
    expect(otlpLogsUrl('https://otel.example.com')).toBe('https://otel.example.com/v1/logs');
    expect(otlpLogsUrl('https://otel.example.com/a//?tenant=1')).toBe(
      'https://otel.example.com/a/v1/logs?tenant=1',
    );
  });

  it('reads headers from their env vars at send time', async () => {
    await sendToSink(
      otlp({ headersFromEnv: { 'DD-API-KEY': 'DD_AUDIT_SINK_SECRET' } }),
      chain(1).map(eventRecord),
      { DD_AUDIT_SINK_SECRET: 'key-1' },
    );

    expect(received[0].headers['dd-api-key']).toBe('key-1');
  });

  it('refuses to send when a header env var is missing or empty, rather than send it empty', async () => {
    const settings = otlp({ headersFromEnv: { Authorization: 'OTEL_AUDIT_SINK_SECRET' } });

    for (const env of [{}, { OTEL_AUDIT_SINK_SECRET: '' }]) {
      const attempt = await sendToSink(settings, chain(1).map(eventRecord), env);
      expect(attempt).toMatchObject({ ok: false, failure: 'misconfigured', statusCode: null });
    }
    expect(received).toHaveLength(0);
  });

  it('refuses a header env var outside the _AUDIT_SINK_SECRET names', async () => {
    const attempt = await sendToSink(
      otlp({ headersFromEnv: { Authorization: 'SEAMLESS_SERVICE_TOKEN' } }),
      chain(1).map(eventRecord),
      { SEAMLESS_SERVICE_TOKEN: 'the-service-token' },
    );

    expect(attempt.failure).toBe('misconfigured');
    expect(received).toHaveLength(0);
  });

  it('refuses a header value that would split the request', async () => {
    const attempt = await sendToSink(
      otlp({ headersFromEnv: { Authorization: 'OTEL_AUDIT_SINK_SECRET' } }),
      chain(1).map(eventRecord),
      { OTEL_AUDIT_SINK_SECRET: 'a\r\nx-injected: 1' },
    );

    expect(attempt.failure).toBe('misconfigured');
    expect(received).toHaveLength(0);
  });

  it('treats a non-2xx, including a redirect, as a failure', async () => {
    answer = { status: 503 };
    expect(await sendToSink(otlp(), chain(1).map(eventRecord), {})).toMatchObject({
      ok: false,
      statusCode: 503,
      failure: 'http_status',
    });

    answer = { status: 307, headers: { location: 'http://169.254.169.254/' } };
    expect(await sendToSink(otlp(), chain(1).map(eventRecord), {})).toMatchObject({
      ok: false,
      statusCode: 307,
    });
    expect(received).toHaveLength(2);
  });

  it('refuses a private destination in production unless the operator lists the host', async () => {
    const env = { NODE_ENV: 'production' };
    const settings = otlp({ endpoint: `https://127.0.0.1:${httpPort}/` });

    expect(sinkDestinationProblem(settings, env)).toContain('non-public');
    expect(await sendToSink(settings, chain(1).map(eventRecord), env)).toMatchObject({
      ok: false,
      failure: 'refused',
    });
    expect(sinkDestinationProblem(settings, { ...env, CALLOUT_PRIVATE_HOSTS: '127.0.0.1' })).toBe(
      null,
    );
  });

  it('refuses plain http in production', () => {
    expect(
      sinkDestinationProblem(otlp({ endpoint: 'http://otel.example.com' }), {
        NODE_ENV: 'production',
      }),
    ).toBe('endpoint must use https');
  });

  it('never reaches a link-local address, in any mode', async () => {
    const settings = otlp({ endpoint: 'http://169.254.169.254/' });

    expect(sinkDestinationProblem(settings, {})).toContain('never reachable');
    expect((await sendToSink(settings, chain(1).map(eventRecord), {})).failure).toBe('refused');
  });

  it('marks the test record and keeps it out of the chain', () => {
    const body = JSON.parse(otlpLogsBody([testRecord('sink-1')], 'seamless-auth'));
    const [record] = body.resourceLogs[0].scopeLogs[0].logRecords;

    expect(JSON.parse(record.body.stringValue)).toMatchObject({ type: 'test', test: true });
    expect(record.body.stringValue).not.toContain('"hash"');
    expect(record.attributes).toEqual([{ key: 'seamless.audit.test', value: { boolValue: true } }]);
  });
});

/** Splits an octet-counted stream into messages, failing on anything that is not a frame. */
function unframe(stream: Buffer): string[] {
  const messages: string[] = [];
  let offset = 0;
  while (offset < stream.length) {
    const space = stream.indexOf(0x20, offset);
    const length = Number(stream.subarray(offset, space).toString('ascii'));
    if (!Number.isInteger(length) || length <= 0) throw new Error('not octet counted');
    messages.push(stream.subarray(space + 1, space + 1 + length).toString('utf8'));
    offset = space + 1 + length;
  }
  return messages;
}

const RFC5424 =
  /^<(\d{1,3})>1 (\S+) (\S+) (\S+) - (\S+) (\[[^ ]+(?: [a-z]+="(?:[^"\\\]]|\\["\\\]])*")*\]) (.*)$/s;

describe('syslog', () => {
  let tcp: TcpServer;
  let streams: Promise<Buffer>[];

  function collect(socket: NodeJS.ReadableStream) {
    streams.push(
      new Promise((done) => {
        const chunks: Buffer[] = [];
        socket.on('data', (chunk: Buffer) => chunks.push(chunk));
        socket.on('end', () => done(Buffer.concat(chunks)));
      }),
    );
  }

  async function listen(server: TcpServer) {
    await new Promise<void>((done) => server.listen(0, '127.0.0.1', done));
    return (server.address() as AddressInfo).port;
  }

  beforeEach(() => {
    streams = [];
  });

  afterEach(async () => {
    if (tcp?.listening) await new Promise<void>((done) => tcp.close(() => done()));
  });

  it('frames RFC 5424 messages with octet counting, the export line as MSG', async () => {
    tcp = createTcpServer((socket) => {
      collect(socket);
      socket.on('end', () => socket.end());
    });
    const port = await listen(tcp);
    const events = chain(3);

    const attempt = await sendToSink(syslog(port), events.map(eventRecord), {});
    expect(attempt).toMatchObject({ ok: true, failure: null, statusCode: null });

    const messages = unframe(await streams[0]);
    expect(messages).toHaveLength(3);

    const parsed = messages.map((message) => {
      const match = RFC5424.exec(message);
      if (!match) throw new Error(`not RFC 5424: ${message}`);
      const [, pri, timestamp, , appName, msgId, sd, msg] = match;
      return { pri: Number(pri), timestamp, appName, msgId, sd, msg };
    });

    // authpriv (10) * 8 + informational (6), and warning (4) for a suspicious event.
    expect(parsed.map((entry) => entry.pri)).toEqual([86, 84, 86]);
    expect(parsed[0]).toMatchObject({
      timestamp: events[0].createdAt,
      appName: 'seamless-auth',
      msgId: 'audit',
      sd: `[${SYSLOG_SD_ID} seq="1" hash="${events[0].hash}"]`,
    });
    const lines = parsed.map((entry) => entry.msg);
    expect(lines).toEqual(events.map(exportLine));
    expect(verifies(lines)).toBe(true);
  });

  it('counts octets, not characters, so a non-ASCII line frames correctly', () => {
    const message = syslogMessage(eventRecord(chain(3)[2]), syslog(1), 'host');
    const frame = octetFrame(message);

    expect(frame.startsWith(`${Buffer.byteLength(message, 'utf8')} `)).toBe(true);
    expect(Buffer.byteLength(message, 'utf8')).toBeGreaterThan(message.length);
    expect(unframe(Buffer.from(frame, 'utf8'))).toEqual([message]);
  });

  it('marks the test record with its own MSGID and no chain fields', () => {
    const message = syslogMessage(testRecord('sink-1'), syslog(1), 'host');

    expect(message).toMatch(/^<86>1 \S+ host seamless-auth - test \[seamless@67592 test="true"\] /);
    expect(message).not.toContain('seq=');
  });

  it('refuses plain TCP in production, before connecting', async () => {
    let connected = false;
    tcp = createTcpServer(() => (connected = true));
    const port = await listen(tcp);
    const env = { NODE_ENV: 'production', CALLOUT_PRIVATE_HOSTS: '127.0.0.1' };

    expect(sinkDestinationProblem(syslog(port), env)).toBe('transport must be tls in production');
    expect((await sendToSink(syslog(port), chain(1).map(eventRecord), env)).failure).toBe(
      'misconfigured',
    );
    expect(connected).toBe(false);
  });

  it('refuses a private or link-local host in production', async () => {
    const env = { NODE_ENV: 'production' };

    expect(sinkDestinationProblem(syslog(6514, { transport: 'tls' }), env)).toContain('non-public');
    expect(
      sinkDestinationProblem(syslog(6514, { host: '169.254.169.254', transport: 'tls' }), {}),
    ).toContain('never reachable');
    expect(
      (
        await sendToSink(
          syslog(6514, { host: 'fe80::1', transport: 'tls' }),
          chain(1).map(eventRecord),
          {},
        )
      ).failure,
    ).toBe('refused');
  });

  it('refuses a host that is not a host name, and a client cert without its key', () => {
    expect(sinkDestinationProblem(syslog(1, { host: 'collector.example.com:6514' }), {})).toBe(
      'host is not a host name',
    );
    expect(
      sinkDestinationProblem(
        syslog(1, { host: 'collector.example.com', tlsClientCertEnv: 'CERT_AUDIT_SINK_SECRET' }),
        {},
      ),
    ).toBe('tlsClientCertEnv and tlsClientKeyEnv must be set together');
  });

  it('checks DNS answers at connect time', async () => {
    const attempt = await sendToSink(
      syslog(6514, { host: 'localhost', transport: 'tls' }),
      chain(1).map(eventRecord),
      { NODE_ENV: 'production' },
    );

    expect(attempt.failure).toBe('refused');
  });

  it('fails a send the collector hangs up on before it is written', async () => {
    tcp = createTcpServer((socket) => socket.destroy());
    const port = await listen(tcp);

    expect(
      (await sendToSink(syslog(port, { transport: 'tls' }), chain(1).map(eventRecord), {})).failure,
    ).toBe('connection_failed');
  });

  it('reports a refused connection coarsely', async () => {
    tcp = createTcpServer();
    const port = await listen(tcp);
    await new Promise<void>((done) => tcp.close(() => done()));

    expect((await sendToSink(syslog(port), chain(1).map(eventRecord), {})).failure).toBe(
      'connection_failed',
    );
  });

  describe('over TLS', () => {
    const env = {
      CA_AUDIT_SINK_SECRET: pem('ca.pem'),
      CERT_AUDIT_SINK_SECRET: pem('client.pem'),
      KEY_AUDIT_SINK_SECRET: pem('client.key'),
    };

    async function tlsServer(requestCert: boolean) {
      const peers: (string | null)[] = [];
      tcp = createTlsServer(
        {
          cert: pem('server.pem'),
          key: pem('server.key'),
          ca: pem('ca.pem'),
          requestCert,
          rejectUnauthorized: requestCert,
        },
        (socket: TLSSocket) => {
          peers.push(socket.getPeerCertificate()?.subject?.CN ?? null);
          collect(socket);
          socket.on('end', () => socket.end());
        },
      );
      const port = await listen(tcp);
      return { port, peers };
    }

    it('verifies the collector against the configured CA and checks the name', async () => {
      const { port } = await tlsServer(false);
      const events = chain(2);

      const attempt = await sendToSink(
        syslog(port, { host: 'localhost', transport: 'tls', tlsCaEnv: 'CA_AUDIT_SINK_SECRET' }),
        events.map(eventRecord),
        env,
      );

      expect(attempt).toMatchObject({ ok: true, failure: null });
      const lines = unframe(await streams[0]).map((message) => RFC5424.exec(message)?.[7]);
      expect(lines).toEqual(events.map(exportLine));
    });

    it('presents a client certificate from env vars', async () => {
      const { port, peers } = await tlsServer(true);

      const attempt = await sendToSink(
        syslog(port, {
          host: 'localhost',
          transport: 'tls',
          tlsCaEnv: 'CA_AUDIT_SINK_SECRET',
          tlsClientCertEnv: 'CERT_AUDIT_SINK_SECRET',
          tlsClientKeyEnv: 'KEY_AUDIT_SINK_SECRET',
        }),
        chain(1).map(eventRecord),
        env,
      );

      expect(attempt.ok).toBe(true);
      await streams[0];
      expect(peers).toEqual(['client']);
    });

    it('fails a collector whose certificate is not trusted', async () => {
      const { port } = await tlsServer(false);

      const attempt = await sendToSink(
        syslog(port, { host: 'localhost', transport: 'tls' }),
        chain(1).map(eventRecord),
        {},
      );

      expect(attempt).toMatchObject({ ok: false, failure: 'connection_failed' });
    });

    it('refuses to connect when a named CA env var is unset', async () => {
      const { port } = await tlsServer(false);

      const attempt = await sendToSink(
        syslog(port, { host: 'localhost', transport: 'tls', tlsCaEnv: 'CA_AUDIT_SINK_SECRET' }),
        chain(1).map(eventRecord),
        {},
      );

      expect(attempt.failure).toBe('misconfigured');
      expect(streams).toHaveLength(0);
    });

    it('times out a collector that never completes the handshake', async () => {
      tcp = createTcpServer(() => {});
      const port = await listen(tcp);

      const attempt = await sendToSink(
        syslog(port, { transport: 'tls' }),
        chain(1).map(eventRecord),
        {},
        200,
      );

      expect(attempt.failure).toBe('timed_out');
      tcp.close();
      await new Promise((done) => setImmediate(done));
    });
  });
});
