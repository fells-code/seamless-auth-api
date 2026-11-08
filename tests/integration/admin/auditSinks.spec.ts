import { Application } from 'express';
import request from 'supertest';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

const { query } = vi.hoisted(() => ({ query: vi.fn() }));

vi.mock('../../../src/models/index.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/models/index.js')>();
  return { ...actual, getSequelize: () => ({ query }) };
});

vi.mock('../../../src/lib/auditSinkTransport.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/lib/auditSinkTransport.js')>();
  return { ...actual, sendToSink: vi.fn() };
});

import { createApp } from '../../../src/app';
import { sendToSink } from '../../../src/lib/auditSinkTransport.js';
import { AuditSink } from '../../../src/models/auditSinks.js';
import { Session } from '../../../src/models/sessions.js';
import { AuthEventService } from '../../../src/services/authEventService.js';
import { buildFreshStepUpSession } from '../../factories/sessionFactory';

let app: Application;

const now = new Date('2026-11-07T12:00:00.000Z');
const sinkId = '7d0c3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f';

const otlp = {
  kind: 'otlp',
  endpoint: 'https://otel.example.com/ingest?token=abc',
  headersFromEnv: { 'DD-API-KEY': 'DD_AUDIT_SINK_SECRET' },
  serviceName: 'seamless-auth',
};

function buildSink(overrides: Record<string, unknown> = {}) {
  const record: any = {
    id: sinkId,
    name: 'SIEM',
    kind: 'otlp',
    enabled: true,
    settings: otlp,
    cursorSeq: '40',
    failureCount: 0,
    nextAttemptAt: null,
    lastDeliveredAt: null,
    lastFailure: null,
    lastFailureAt: null,
    createdBy: null,
    createdAt: now,
    updatedAt: now,
    ...overrides,
  };
  record.update = vi.fn(async (values: Record<string, unknown>) => Object.assign(record, values));
  record.destroy = vi.fn();
  return record;
}

beforeAll(async () => {
  app = await createApp();
});

beforeEach(() => {
  vi.clearAllMocks();
  (Session.findOne as any).mockResolvedValue(buildFreshStepUpSession());
  query.mockResolvedValue([{ head: '42', oldest: '1' }]);
});

describe('audit sinks', () => {
  it('lists sinks with their lag behind the chain head', async () => {
    vi.mocked(AuditSink.findAll).mockResolvedValue([buildSink()]);

    const res = await request(app).get('/admin/audit-sinks');

    expect(res.status).toBe(200);
    expect(res.body.sinks[0]).toMatchObject({
      id: sinkId,
      settings: { kind: 'otlp' },
      status: { cursorSeq: 40, lagEvents: 2 },
    });
  });

  it('creates a sink at the chain head and audits it without the query string', async () => {
    vi.mocked(AuditSink.create).mockImplementation(async (values: any) => buildSink(values));

    const res = await request(app)
      .post('/admin/audit-sinks')
      .send({ name: 'SIEM', settings: otlp });

    expect(res.status).toBe(201);
    expect(res.body.sink.status).toMatchObject({ cursorSeq: 42, lagEvents: 0 });
    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'admin_audit_sink_created',
        metadata: expect.objectContaining({
          destination: 'https://otel.example.com/ingest',
          kind: 'otlp',
          cursorSeq: 42,
        }),
      }),
    );
  });

  it('refuses a destination pointing at the cloud metadata address', async () => {
    const res = await request(app)
      .post('/admin/audit-sinks')
      .send({ name: 'SIEM', settings: { ...otlp, endpoint: 'http://169.254.169.254/' } });

    expect(res.status).toBe(400);
    expect(res.body.error).toContain('never reachable');
    expect(AuditSink.create).not.toHaveBeenCalled();
  });

  it('refuses plain TCP syslog in production', async () => {
    vi.stubEnv('NODE_ENV', 'production');

    const res = await request(app)
      .post('/admin/audit-sinks')
      .send({
        name: 'SIEM',
        settings: { kind: 'syslog', host: 'collector.example.com', transport: 'tcp' },
      });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('transport must be tls in production');
  });

  it('refuses a credential env var outside the _AUDIT_SINK_SECRET names', async () => {
    const res = await request(app)
      .post('/admin/audit-sinks')
      .send({
        name: 'SIEM',
        settings: { ...otlp, headersFromEnv: { Authorization: 'SEAMLESS_SERVICE_TOKEN' } },
      });

    expect(res.status).toBe(400);
    expect(AuditSink.create).not.toHaveBeenCalled();
  });

  it('reads, updates and deletes a sink, auditing each write', async () => {
    const record = buildSink();
    vi.mocked(AuditSink.findByPk).mockResolvedValue(record);

    expect((await request(app).get(`/admin/audit-sinks/${sinkId}`)).status).toBe(200);

    const updated = await request(app)
      .patch(`/admin/audit-sinks/${sinkId}`)
      .send({
        enabled: false,
        settings: { kind: 'syslog', host: 'collector.example.com' },
      });
    expect(updated.status).toBe(200);
    expect(updated.body.sink).toMatchObject({
      enabled: false,
      settings: { kind: 'syslog', port: 6514, transport: 'tls', facility: 10 },
    });

    const deleted = await request(app).delete(`/admin/audit-sinks/${sinkId}`);
    expect(deleted.status).toBe(200);
    expect(record.destroy).toHaveBeenCalled();

    const calls = vi.mocked(AuthEventService.log).mock.calls.map(([options]) => options);
    expect(calls.map((options) => options.type)).toEqual([
      'admin_audit_sink_updated',
      'admin_audit_sink_deleted',
    ]);
    expect(calls[0].metadata).toMatchObject({
      changed: ['settings', 'enabled'],
      destination: 'tls://collector.example.com:6514',
    });
  });

  it('passes an unexpected failure to the error handler', async () => {
    vi.mocked(AuditSink.findByPk).mockRejectedValue(new Error('database unavailable'));

    const res = await request(app).get(`/admin/audit-sinks/${sinkId}`);

    expect(res.status).toBe(500);
  });

  it('refuses an empty update', async () => {
    const res = await request(app).patch(`/admin/audit-sinks/${sinkId}`).send({});

    expect(res.status).toBe(400);
  });

  it('answers 404 for a sink that does not exist', async () => {
    for (const send of [
      () => request(app).get(`/admin/audit-sinks/${sinkId}`),
      () => request(app).patch(`/admin/audit-sinks/${sinkId}`).send({ enabled: true }),
      () => request(app).delete(`/admin/audit-sinks/${sinkId}`),
      () => request(app).post(`/admin/audit-sinks/${sinkId}/test`),
    ]) {
      expect((await send()).status).toBe(404);
    }
  });

  it('sends a test record and returns the outcome', async () => {
    vi.mocked(AuditSink.findByPk).mockResolvedValue(buildSink());
    vi.mocked(sendToSink).mockResolvedValue({
      ok: false,
      failure: 'misconfigured',
      statusCode: null,
      durationMs: 3,
    });

    const res = await request(app).post(`/admin/audit-sinks/${sinkId}/test`);

    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      ok: false,
      failure: 'misconfigured',
      statusCode: null,
      durationMs: 3,
    });
    const [, records] = vi.mocked(sendToSink).mock.calls[0];
    expect(records).toHaveLength(1);
    expect(records[0].event).toBeNull();
  });
});
