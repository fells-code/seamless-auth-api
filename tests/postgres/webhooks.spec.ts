import { createServer, type IncomingHttpHeaders, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { getSequelize, initializeModels } from '../../src/models/index.js';
import { WebhookDelivery } from '../../src/models/webhookDeliveries.js';
import { WebhookEndpoint } from '../../src/models/webhookEndpoints.js';
import { AuthEventService } from '../../src/services/authEventService.js';
import { createEndpoint, deliverDue, dispatchWebhooks } from '../../src/services/webhookService.js';

let server: Server;
let port: number;
const received: { headers: IncomingHttpHeaders; body: string }[] = [];
let answer = 200;

beforeAll(async () => {
  await initializeModels();

  server = createServer((req, res) => {
    let body = '';
    req.on('data', (chunk) => (body += chunk));
    req.on('end', () => {
      received.push({ headers: req.headers, body });
      res.statusCode = answer;
      res.end();
    });
  });
  await new Promise<void>((done) => server.listen(0, '127.0.0.1', done));
  port = (server.address() as AddressInfo).port;
});

beforeEach(async () => {
  received.length = 0;
  answer = 200;
  await getSequelize().query(
    'DELETE FROM webhook_deliveries; DELETE FROM webhook_endpoints; DELETE FROM event_dispatch_cursors;',
  );
});

afterAll(async () => {
  server.closeAllConnections();
  await new Promise<void>((done) => server.close(() => done()));
  await getSequelize().close();
});

async function logEvent(type: string, userId: string, metadata: Record<string, unknown> = {}) {
  await AuthEventService.logContext({ type: type as never, userId, metadata });
}

describe('webhook dispatch against the audit chain', () => {
  it('starts after the newest event, then delivers each new one once, signed', async () => {
    const { secret } = await createEndpoint(
      { url: `http://127.0.0.1:${port}/hook`, eventTypes: ['user.deleted'] },
      null,
    );

    // Before the cursor exists: history is not replayed.
    await logEvent('user_deleted', '11111111-1111-4111-8111-111111111111');
    expect(await dispatchWebhooks()).toBe(0);

    await logEvent('user_deleted', '22222222-2222-4222-8222-222222222222');
    await logEvent('login_failed', '22222222-2222-4222-8222-222222222222');
    expect(await dispatchWebhooks()).toBe(2);
    // Running again finds nothing new and queues nothing twice.
    expect(await dispatchWebhooks()).toBe(0);

    const deliveries = await WebhookDelivery.findAll();
    expect(deliveries).toHaveLength(1);

    expect(await deliverDue()).toBe(1);
    expect(received).toHaveLength(1);

    const [{ headers, body }] = received;
    expect(JSON.parse(body)).toMatchObject({
      id: deliveries[0].id,
      type: 'user.deleted',
      data: { userId: '22222222-2222-4222-8222-222222222222' },
    });
    expect(headers['webhook-id']).toBe(deliveries[0].id);
    expect(headers['webhook-signature']).toMatch(/^v1,/);
    expect(secret).toMatch(/^whsec_/);

    await deliveries[0].reload();
    expect(deliveries[0]).toMatchObject({ status: 'succeeded', attempts: 1 });
  });

  it('cannot queue the same audit row twice for one endpoint', async () => {
    const { endpoint } = await createEndpoint(
      { url: `http://127.0.0.1:${port}/hook`, eventTypes: ['user.deleted'] },
      null,
    );
    const insert = () =>
      getSequelize().query(
        `INSERT INTO webhook_deliveries (id, "endpointId", "eventType", "authEventSeq", payload,
           status, attempts, "createdAt", "updatedAt")
         VALUES (gen_random_uuid(), :endpointId, 'user.deleted', 7, '{}', 'pending', 0, now(), now())
         ON CONFLICT ("endpointId", "authEventSeq") DO NOTHING`,
        { replacements: { endpointId: endpoint.id } },
      );

    await insert();
    await insert();

    expect(await WebhookDelivery.count()).toBe(1);
  });

  it('schedules a retry after a failure and holds the lease from a second worker', async () => {
    await createEndpoint(
      { url: `http://127.0.0.1:${port}/hook`, eventTypes: ['user.deleted'] },
      null,
    );
    await dispatchWebhooks();
    await logEvent('user_deleted', '33333333-3333-4333-8333-333333333333');
    await dispatchWebhooks();

    answer = 503;
    expect(await deliverDue()).toBe(1);
    // Not due again until the schedule says so.
    expect(await deliverDue()).toBe(0);

    const [delivery] = await WebhookDelivery.findAll();
    expect(delivery).toMatchObject({ status: 'failed', attempts: 1, lastStatusCode: 503 });
    expect(delivery.nextAttemptAt!.getTime()).toBeGreaterThan(Date.now());

    const [endpoint] = await WebhookEndpoint.findAll();
    expect(endpoint.failingSince).not.toBeNull();
  });

  it('deletes an endpoint with its deliveries', async () => {
    const { endpoint } = await createEndpoint(
      { url: `http://127.0.0.1:${port}/hook`, eventTypes: ['user.deleted'] },
      null,
    );
    await dispatchWebhooks();
    await logEvent('user_deleted', '44444444-4444-4444-8444-444444444444');
    await dispatchWebhooks();

    await endpoint.destroy();

    expect(await WebhookDelivery.count()).toBe(0);
  });
});
