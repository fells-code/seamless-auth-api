import { Application } from 'express';
import request from 'supertest';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/lib/calloutTransport.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/lib/calloutTransport.js')>();
  return { ...actual, calloutRequest: vi.fn() };
});

import { createApp } from '../../../src/app';
import { calloutRequest } from '../../../src/lib/calloutTransport.js';
import { encryptCalloutSecret } from '../../../src/lib/calloutSigning.js';
import { Session } from '../../../src/models/sessions.js';
import { WebhookDelivery } from '../../../src/models/webhookDeliveries.js';
import { WebhookEndpoint } from '../../../src/models/webhookEndpoints.js';
import { AuthEventService } from '../../../src/services/authEventService.js';
import { buildFreshStepUpSession } from '../../factories/sessionFactory';

let app: Application;

const now = new Date('2026-11-07T12:00:00.000Z');
const endpointId = '5b8a1c2d-3e4f-4a5b-8c6d-7e8f9a0b1c2d';
const deliveryId = '6c9b2d3e-4f5a-4b6c-9d7e-8f9a0b1c2d3e';

function buildEndpoint(overrides: Record<string, unknown> = {}) {
  const sealed = encryptCalloutSecret('whsec_' + Buffer.alloc(32, 2).toString('base64'));
  const record: any = {
    id: endpointId,
    url: 'https://hooks.example.com/seamless',
    description: null,
    eventTypes: ['user.created'],
    enabled: true,
    disabledReason: null,
    version: 1,
    secretCiphertext: sealed.ciphertext,
    secretIv: sealed.iv,
    secretTag: sealed.tag,
    previousSecretCiphertext: null,
    previousSecretIv: null,
    previousSecretTag: null,
    previousSecretExpiresAt: null,
    failingSince: null,
    createdAt: now,
    updatedAt: now,
    ...overrides,
  };
  record.update = vi.fn(async (values: Record<string, unknown>) => Object.assign(record, values));
  record.destroy = vi.fn();
  return record;
}

function buildDelivery(overrides: Record<string, unknown> = {}) {
  const record: any = {
    id: deliveryId,
    endpointId,
    eventType: 'user.created',
    authEventSeq: '10',
    payload: JSON.stringify({
      id: deliveryId,
      type: 'user.created',
      version: 1,
      timestamp: now.toISOString(),
      data: { userId: 'u', email: null, phone: null },
    }),
    status: 'dead',
    attempts: 8,
    nextAttemptAt: null,
    lastAttemptAt: now,
    lastStatusCode: 500,
    lastFailure: 'http_status',
    createdAt: now,
    ...overrides,
  };
  record.update = vi.fn(async (values: Record<string, unknown>) => Object.assign(record, values));
  return record;
}

beforeAll(async () => {
  app = await createApp();
});

beforeEach(() => {
  vi.clearAllMocks();
  (Session.findOne as any).mockResolvedValue(buildFreshStepUpSession());
});

describe('webhook endpoints', () => {
  it('lists endpoints without their secrets', async () => {
    vi.mocked(WebhookEndpoint.findAll).mockResolvedValue([buildEndpoint()]);

    const res = await request(app).get('/admin/webhooks');

    expect(res.status).toBe(200);
    expect(res.body.endpoints[0]).toMatchObject({ id: endpointId, version: 1 });
    expect(JSON.stringify(res.body)).not.toMatch(/secret(Ciphertext|Iv|Tag)|whsec_/);
  });

  it('creates an endpoint, returns the secret once and audits it', async () => {
    vi.mocked(WebhookEndpoint.create).mockImplementation(async (values: any) =>
      buildEndpoint(values),
    );

    const res = await request(app)
      .post('/admin/webhooks')
      .send({ url: 'https://hooks.example.com/a?token=abc', eventTypes: ['user.created'] });

    expect(res.status).toBe(201);
    expect(res.body.secret).toMatch(/^whsec_/);
    // The audit log is permanent, so a token in the query string must not reach it.
    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'admin_webhook_created',
        metadata: expect.objectContaining({ url: 'https://hooks.example.com/a' }),
      }),
    );
  });

  it('refuses a URL pointing at the cloud metadata address', async () => {
    const res = await request(app)
      .post('/admin/webhooks')
      .send({ url: 'http://169.254.169.254/latest', eventTypes: ['user.created'] });

    expect(res.status).toBe(400);
    expect(res.body.error).toContain('never reachable');
    expect(WebhookEndpoint.create).not.toHaveBeenCalled();
  });

  it('refuses an unknown event type and the test type', async () => {
    for (const eventTypes of [['user.renamed'], ['webhook.test']]) {
      const res = await request(app)
        .post('/admin/webhooks')
        .send({ url: 'https://hooks.example.com/a', eventTypes });
      expect(res.status).toBe(400);
    }
  });

  it('reads, updates and deletes an endpoint, auditing each write', async () => {
    const record = buildEndpoint();
    vi.mocked(WebhookEndpoint.findByPk).mockResolvedValue(record);

    expect((await request(app).get(`/admin/webhooks/${endpointId}`)).status).toBe(200);

    const updated = await request(app)
      .patch(`/admin/webhooks/${endpointId}`)
      .send({ enabled: false });
    expect(updated.status).toBe(200);
    expect(updated.body.endpoint).toMatchObject({ enabled: false, disabledReason: 'manual' });

    const deleted = await request(app).delete(`/admin/webhooks/${endpointId}`);
    expect(deleted.status).toBe(200);
    expect(record.destroy).toHaveBeenCalled();

    const types = vi.mocked(AuthEventService.log).mock.calls.map(([options]) => options.type);
    expect(types).toEqual(['admin_webhook_updated', 'admin_webhook_deleted']);
  });

  it('answers 404 for an endpoint that does not exist', async () => {
    for (const send of [
      () => request(app).get(`/admin/webhooks/${endpointId}`),
      () => request(app).patch(`/admin/webhooks/${endpointId}`).send({ enabled: true }),
      () => request(app).delete(`/admin/webhooks/${endpointId}`),
      () => request(app).post(`/admin/webhooks/${endpointId}/secret`),
      () => request(app).post(`/admin/webhooks/${endpointId}/test`),
    ]) {
      expect((await send()).status).toBe(404);
    }
  });

  it('rotates the secret and returns the new one', async () => {
    vi.mocked(WebhookEndpoint.findByPk).mockResolvedValue(buildEndpoint());

    const res = await request(app).post(`/admin/webhooks/${endpointId}/secret`);

    expect(res.status).toBe(200);
    expect(res.body.secret).toMatch(/^whsec_/);
    expect(res.body.previousSecretExpiresAt).toBeDefined();
    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({ type: 'admin_webhook_secret_rotated' }),
    );
  });

  it('sends a test event and reports the result', async () => {
    vi.mocked(WebhookEndpoint.findByPk).mockResolvedValue(buildEndpoint());
    vi.mocked(WebhookDelivery.create).mockImplementation(async (values: any) =>
      buildDelivery(values),
    );
    vi.mocked(calloutRequest).mockResolvedValue({
      status: 200,
      headers: {},
      body: Buffer.alloc(0),
    });

    const res = await request(app).post(`/admin/webhooks/${endpointId}/test`);

    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ ok: true, failure: null, statusCode: 200 });
  });
});

describe('webhook deliveries', () => {
  it('lists deliveries, filtered to dead letters', async () => {
    vi.mocked(WebhookDelivery.findAll).mockResolvedValue([buildDelivery()]);

    const res = await request(app).get('/admin/webhook-deliveries?status=dead');

    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ deliveries: [{ id: deliveryId }], nextCursor: null });
  });

  it('refuses a cursor it did not issue', async () => {
    const res = await request(app).get('/admin/webhook-deliveries?cursor=nope');

    expect(res.status).toBe(400);
  });

  it('shows a delivery with its event', async () => {
    vi.mocked(WebhookDelivery.findByPk).mockResolvedValue(buildDelivery());

    const res = await request(app).get(`/admin/webhook-deliveries/${deliveryId}`);

    expect(res.status).toBe(200);
    expect(res.body.delivery.event).toMatchObject({ type: 'user.created', id: deliveryId });
  });

  it('redelivers and audits it', async () => {
    const record = buildDelivery();
    vi.mocked(WebhookDelivery.findByPk).mockResolvedValue(record);
    vi.mocked(WebhookEndpoint.findByPk).mockResolvedValue(buildEndpoint());
    vi.mocked(calloutRequest).mockResolvedValue({
      status: 202,
      headers: {},
      body: Buffer.alloc(0),
    });

    const res = await request(app).post(`/admin/webhook-deliveries/${deliveryId}/redeliver`);

    expect(res.status).toBe(200);
    expect(res.body.delivery).toMatchObject({ status: 'succeeded', attempts: 9 });
    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({ type: 'admin_webhook_redelivered' }),
    );
  });

  it('answers 404 for a delivery that does not exist', async () => {
    expect((await request(app).get(`/admin/webhook-deliveries/${deliveryId}`)).status).toBe(404);
    expect(
      (await request(app).post(`/admin/webhook-deliveries/${deliveryId}/redeliver`)).status,
    ).toBe(404);
  });

  it('rethrows an unexpected error', async () => {
    vi.mocked(WebhookDelivery.findAll).mockRejectedValue(new Error('database down'));

    expect((await request(app).get('/admin/webhook-deliveries')).status).toBe(500);
  });
});
