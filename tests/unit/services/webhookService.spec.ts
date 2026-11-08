import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const { query, transaction } = vi.hoisted(() => {
  const query = vi.fn();
  const transaction = vi.fn(async (fn: (t: unknown) => unknown) => fn({ id: 'tx' }));
  return { query, transaction };
});

vi.mock('../../../src/models/index.js', () => ({
  getSequelize: () => ({ query, transaction }),
}));

vi.mock('../../../src/models/webhookEndpoints.js', () => ({
  WebhookEndpoint: {
    findAll: vi.fn(),
    findByPk: vi.fn(),
    create: vi.fn(),
  },
}));

vi.mock('../../../src/models/webhookDeliveries.js', () => ({
  WebhookDelivery: {
    findAll: vi.fn(),
    findByPk: vi.fn(),
    create: vi.fn(),
    update: vi.fn(),
    destroy: vi.fn(),
  },
}));

vi.mock('../../../src/lib/calloutTransport.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/lib/calloutTransport.js')>();
  return { ...actual, calloutRequest: vi.fn() };
});

import { CalloutError, calloutRequest } from '../../../src/lib/calloutTransport.js';
import { encryptCalloutSecret, generateCalloutSecret } from '../../../src/lib/calloutSigning.js';
import { User } from '../../../src/models/users.js';
import { WebhookDelivery } from '../../../src/models/webhookDeliveries.js';
import { WebhookEndpoint } from '../../../src/models/webhookEndpoints.js';
import { AuthEventService } from '../../../src/services/authEventService.js';
import {
  attemptDelivery,
  createEndpoint,
  deleteEndpoint,
  deliverDue,
  dispatchWebhooks,
  getDelivery,
  getEndpoint,
  listDeliveries,
  listEndpoints,
  nextAttemptAt,
  pruneDeliveries,
  redeliver,
  rotateEndpointSecret,
  runWebhookTick,
  sendSigned,
  sendTestEvent,
  serializeDelivery,
  serializeEndpoint,
  signingSecrets,
  startWebhookDelivery,
  updateEndpoint,
  WebhookError,
} from '../../../src/services/webhookService.js';

const at = new Date('2026-11-07T12:00:00.000Z');
const secret = 'whsec_' + Buffer.alloc(32, 1).toString('base64');

function endpoint(overrides: Record<string, unknown> = {}) {
  const sealed = encryptCalloutSecret(secret);
  const record: any = {
    id: 'endpoint-1',
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
    createdAt: at,
    updatedAt: at,
    ...overrides,
  };
  record.update = vi.fn(async (changes: Record<string, unknown>) => Object.assign(record, changes));
  record.destroy = vi.fn();
  return record;
}

function delivery(overrides: Record<string, unknown> = {}) {
  const record: any = {
    id: 'delivery-1',
    endpointId: 'endpoint-1',
    eventType: 'user.created',
    authEventSeq: '10',
    payload: '{"type":"user.created"}',
    status: 'pending',
    attempts: 0,
    nextAttemptAt: at,
    lastAttemptAt: null,
    lastStatusCode: null,
    lastFailure: null,
    createdAt: at,
    ...overrides,
  };
  record.update = vi.fn(async (changes: Record<string, unknown>) => Object.assign(record, changes));
  return record;
}

function responds(status: number, headers: Record<string, string> = {}) {
  vi.mocked(calloutRequest).mockResolvedValue({ status, headers, body: Buffer.alloc(0) });
}

beforeEach(() => {
  transaction.mockImplementation(async (fn: (t: unknown) => unknown) => fn({ id: 'tx' }));
});

afterEach(() => {
  vi.useRealTimers();
});

describe('endpoints', () => {
  it('creates an endpoint with an encrypted secret and returns the secret once', async () => {
    vi.mocked(WebhookEndpoint.create).mockImplementation(async (values: any) => endpoint(values));

    const { endpoint: created, secret: issued } = await createEndpoint(
      { url: 'https://hooks.example.com/a', eventTypes: ['user.created'] },
      'admin-1',
    );

    const stored = vi.mocked(WebhookEndpoint.create).mock.calls[0][0] as any;
    expect(issued).toMatch(/^whsec_/);
    expect(stored.secretCiphertext).toBeDefined();
    expect(JSON.stringify(stored)).not.toContain(issued.slice(6));
    expect(stored).toMatchObject({ enabled: true, description: null, createdBy: 'admin-1' });
    expect(created.url).toBe('https://hooks.example.com/a');
  });

  it('keeps an explicit description and enabled flag', async () => {
    vi.mocked(WebhookEndpoint.create).mockImplementation(async (values: any) => endpoint(values));

    await createEndpoint(
      {
        url: 'https://hooks.example.com/a',
        eventTypes: ['user.created'],
        description: 'CRM',
        enabled: false,
      },
      null,
    );

    expect(vi.mocked(WebhookEndpoint.create).mock.calls[0][0]).toMatchObject({
      description: 'CRM',
      enabled: false,
    });
  });

  it('refuses a URL no callout may reach', async () => {
    await expect(
      createEndpoint({ url: 'http://169.254.169.254/', eventTypes: ['user.created'] }, null),
    ).rejects.toMatchObject({ status: 400 });
    expect(WebhookEndpoint.create).not.toHaveBeenCalled();
  });

  it('refuses to store a secret in production without the encryption key', async () => {
    vi.stubEnv('NODE_ENV', 'production');
    vi.stubEnv('CALLOUT_SECRET_ENCRYPTION_KEY', '');

    await expect(
      createEndpoint({ url: 'https://hooks.example.com/a', eventTypes: ['user.created'] }, null),
    ).rejects.toMatchObject({ status: 409 });
  });

  it('lists, reads and deletes', async () => {
    const record = endpoint();
    vi.mocked(WebhookEndpoint.findAll).mockResolvedValue([record]);
    vi.mocked(WebhookEndpoint.findByPk).mockResolvedValue(record);

    expect(await listEndpoints()).toEqual([record]);
    expect(await getEndpoint('endpoint-1')).toBe(record);
    expect(await deleteEndpoint('endpoint-1')).toBe(record);
    expect(record.destroy).toHaveBeenCalled();
  });

  it('answers 404 for a missing endpoint', async () => {
    vi.mocked(WebhookEndpoint.findByPk).mockResolvedValue(null);

    await expect(getEndpoint('missing')).rejects.toBeInstanceOf(WebhookError);
  });

  it('updates fields, and turning an endpoint on clears why it was off', async () => {
    const record = endpoint({ enabled: false, disabledReason: 'failing', failingSince: at });
    vi.mocked(WebhookEndpoint.findByPk).mockResolvedValue(record);

    await updateEndpoint('endpoint-1', {
      url: 'https://hooks.example.com/b',
      description: null,
      eventTypes: ['user.deleted'],
      enabled: true,
    });

    expect(record).toMatchObject({
      url: 'https://hooks.example.com/b',
      eventTypes: ['user.deleted'],
      enabled: true,
      disabledReason: null,
      failingSince: null,
    });
  });

  it('records a manual disable', async () => {
    const record = endpoint();
    vi.mocked(WebhookEndpoint.findByPk).mockResolvedValue(record);

    await updateEndpoint('endpoint-1', { enabled: false });

    expect(record.disabledReason).toBe('manual');
  });

  it('refuses an update to a URL no callout may reach', async () => {
    vi.mocked(WebhookEndpoint.findByPk).mockResolvedValue(endpoint());

    await expect(
      updateEndpoint('endpoint-1', { url: 'https://user:pw@hooks.example.com/' }),
    ).rejects.toMatchObject({ status: 400 });
  });

  it('rotates the secret, keeping the old one signing for a day', async () => {
    vi.useFakeTimers({ now: at });
    const record = endpoint();
    const oldCiphertext = record.secretCiphertext;
    vi.mocked(WebhookEndpoint.findByPk).mockResolvedValue(record);

    const { secret: issued, previousSecretExpiresAt } = await rotateEndpointSecret('endpoint-1');

    expect(record.previousSecretCiphertext).toBe(oldCiphertext);
    expect(previousSecretExpiresAt.toISOString()).toBe('2026-11-08T12:00:00.000Z');
    expect(signingSecrets(record)).toEqual([issued, secret]);
  });

  it('stops signing with the previous secret once its overlap ends', () => {
    const sealed = encryptCalloutSecret(generateCalloutSecret());
    const record = endpoint({
      previousSecretCiphertext: sealed.ciphertext,
      previousSecretIv: sealed.iv,
      previousSecretTag: sealed.tag,
      previousSecretExpiresAt: new Date(at.getTime() - 1),
    });

    expect(signingSecrets(record, at)).toEqual([secret]);
    expect(serializeEndpoint(record).previousSecretExpiresAt).toBeNull();
  });

  it('serializes an endpoint mid-rotation', () => {
    const future = new Date(Date.now() + 60_000);
    expect(serializeEndpoint(endpoint({ previousSecretExpiresAt: future }))).toMatchObject({
      previousSecretExpiresAt: future.toISOString(),
      version: 1,
    });
  });
});

describe('sendSigned', () => {
  it('signs the request and treats a 2xx as delivered', async () => {
    responds(204);

    const attempt = await sendSigned('https://hooks.example.com/', 'id-1', '{}', [secret]);

    const [, request] = vi.mocked(calloutRequest).mock.calls[0];
    expect(request.headers?.['webhook-id']).toBe('id-1');
    expect(request.headers?.['webhook-signature']).toMatch(/^v1,/);
    expect(attempt).toMatchObject({ ok: true, statusCode: 204, failure: null });
  });

  it.each([
    [301, 'a redirect, which is not followed'],
    [500, 'a server error'],
  ])('treats %s as a failure (%s)', async (status) => {
    responds(status);

    expect(await sendSigned('https://hooks.example.com/', 'id', '{}', [secret])).toMatchObject({
      ok: false,
      statusCode: status,
      failure: 'http_status',
    });
  });

  it.each([
    ['120', 120],
    ['Sat, 07 Nov 2026 12:10:00 GMT', 600],
    ['soon', null],
  ])('reads Retry-After %j', async (header, seconds) => {
    vi.useFakeTimers({ now: at });
    responds(429, { 'retry-after': header });

    const attempt = await sendSigned('https://hooks.example.com/', 'id', '{}', [secret]);

    expect(attempt.retryAfterSeconds).toBe(seconds);
  });

  it('reads the first of repeated Retry-After headers', async () => {
    vi.mocked(calloutRequest).mockResolvedValue({
      status: 503,
      headers: { 'retry-after': ['30', '60'] },
      body: Buffer.alloc(0),
    });

    expect(
      (await sendSigned('https://hooks.example.com/', 'id', '{}', [secret])).retryAfterSeconds,
    ).toBe(30);
  });

  it('reports a transport failure by its coarse reason', async () => {
    vi.mocked(calloutRequest).mockRejectedValue(new CalloutError('refused', 'internal detail'));

    expect(await sendSigned('https://hooks.example.com/', 'id', '{}', [secret])).toMatchObject({
      ok: false,
      failure: 'refused',
      statusCode: null,
    });
  });

  it('reports an unexpected error as a failed connection', async () => {
    vi.mocked(calloutRequest).mockRejectedValue(new Error('boom'));

    expect((await sendSigned('https://hooks.example.com/', 'id', '{}', [secret])).failure).toBe(
      'connection_failed',
    );
  });
});

describe('nextAttemptAt', () => {
  beforeEach(() => {
    vi.spyOn(Math, 'random').mockReturnValue(0);
  });

  it('follows the schedule, then stops', () => {
    expect(nextAttemptAt(1, at, null)?.toISOString()).toBe('2026-11-07T12:00:05.000Z');
    expect(nextAttemptAt(7, at, null)?.toISOString()).toBe('2026-11-08T12:00:00.000Z');
    expect(nextAttemptAt(8, at, null)).toBeNull();
  });

  it('honors a longer Retry-After, up to the longest step', () => {
    expect(nextAttemptAt(1, at, 600)?.toISOString()).toBe('2026-11-07T12:10:00.000Z');
    expect(nextAttemptAt(1, at, 10 * 86400)?.toISOString()).toBe('2026-11-08T12:00:00.000Z');
    expect(nextAttemptAt(3, at, 1)?.toISOString()).toBe('2026-11-07T12:30:00.000Z');
  });
});

describe('attemptDelivery', () => {
  beforeEach(() => {
    vi.spyOn(Math, 'random').mockReturnValue(0);
    vi.useFakeTimers({ now: at });
  });

  it('marks a delivered event and clears a failing streak', async () => {
    responds(200);
    const record = delivery();
    const target = endpoint({ failingSince: new Date(at.getTime() - 1000) });

    await attemptDelivery(record, target);

    expect(record).toMatchObject({ status: 'succeeded', attempts: 1, nextAttemptAt: null });
    expect(target.failingSince).toBeNull();
  });

  it('leaves a healthy endpoint alone on success', async () => {
    responds(200);
    const target = endpoint();

    await attemptDelivery(delivery(), target);

    expect(target.update).not.toHaveBeenCalled();
  });

  it('schedules a retry and starts the failing streak', async () => {
    responds(500);
    const record = delivery();
    const target = endpoint();

    await attemptDelivery(record, target);

    expect(record).toMatchObject({
      status: 'failed',
      attempts: 1,
      lastStatusCode: 500,
      lastFailure: 'http_status',
    });
    expect(record.nextAttemptAt.toISOString()).toBe('2026-11-07T12:00:05.000Z');
    expect(target.failingSince).toEqual(at);
  });

  it('dead-letters a delivery after the last scheduled attempt', async () => {
    responds(500);
    const record = delivery({ attempts: 7 });

    await attemptDelivery(record, endpoint({ failingSince: at }));

    expect(record).toMatchObject({ status: 'dead', attempts: 8, nextAttemptAt: null });
  });

  it('disables an endpoint that answers 410, and audits it', async () => {
    responds(410);
    const target = endpoint();

    await attemptDelivery(delivery(), target);

    expect(target).toMatchObject({ enabled: false, disabledReason: 'gone' });
    expect(AuthEventService.logContext).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'webhook_endpoint_disabled',
        metadata: { endpointId: 'endpoint-1', reason: 'gone' },
      }),
    );
  });

  it('disables an endpoint whose deliveries have all failed for three days', async () => {
    responds(503);
    const target = endpoint({ failingSince: new Date(at.getTime() - 3 * 86400 * 1000) });

    await attemptDelivery(delivery(), target);

    expect(target).toMatchObject({ enabled: false, disabledReason: 'failing' });
  });

  it('keeps the start of a failing streak', async () => {
    responds(503);
    const since = new Date(at.getTime() - 3600 * 1000);
    const target = endpoint({ failingSince: since });

    await attemptDelivery(delivery(), target);

    expect(target.failingSince).toBe(since);
    expect(target.update).not.toHaveBeenCalled();
  });

  it('does not disable an endpoint twice', async () => {
    responds(410);
    const target = endpoint({ enabled: false, disabledReason: 'manual' });

    await attemptDelivery(delivery(), target);

    expect(target.disabledReason).toBe('manual');
    expect(AuthEventService.logContext).not.toHaveBeenCalled();
  });
});

describe('test events and redelivery', () => {
  it('sends webhook.test once and logs it, without touching the endpoint', async () => {
    responds(500);
    const target = endpoint();
    vi.mocked(WebhookEndpoint.findByPk).mockResolvedValue(target);
    vi.mocked(WebhookDelivery.create).mockImplementation(async (values: any) => delivery(values));

    const result = await sendTestEvent('endpoint-1');

    const created = vi.mocked(WebhookDelivery.create).mock.calls[0][0] as any;
    expect(JSON.parse(created.payload)).toMatchObject({
      type: 'webhook.test',
      version: 1,
      data: { endpointId: 'endpoint-1' },
    });
    expect(result).toMatchObject({ ok: false, failure: 'http_status', statusCode: 500 });
    expect(target.update).not.toHaveBeenCalled();
  });

  it('reports a passing test', async () => {
    responds(200);
    vi.mocked(WebhookEndpoint.findByPk).mockResolvedValue(endpoint());
    const record = delivery({ eventType: 'webhook.test' });
    vi.mocked(WebhookDelivery.create).mockResolvedValue(record);

    expect((await sendTestEvent('endpoint-1')).ok).toBe(true);
    expect(record.status).toBe('succeeded');
  });

  it('redelivers with the same id and body', async () => {
    responds(200);
    const record = delivery({ status: 'dead', attempts: 8 });
    vi.mocked(WebhookDelivery.findByPk).mockResolvedValue(record);
    vi.mocked(WebhookEndpoint.findByPk).mockResolvedValue(endpoint());

    await redeliver('delivery-1');

    const [, request] = vi.mocked(calloutRequest).mock.calls[0];
    expect(request.headers?.['webhook-id']).toBe('delivery-1');
    expect(request.body).toBe(record.payload);
    expect(record.status).toBe('succeeded');
  });

  it('answers 404 for a missing delivery', async () => {
    vi.mocked(WebhookDelivery.findByPk).mockResolvedValue(null);

    await expect(getDelivery('missing')).rejects.toMatchObject({ status: 404 });
  });
});

describe('listDeliveries', () => {
  it('pages newest first with an opaque cursor', async () => {
    const rows = [
      delivery({ id: 'c', createdAt: new Date(at.getTime() + 2) }),
      delivery({ id: 'b', createdAt: new Date(at.getTime() + 1) }),
      delivery({ id: 'a', createdAt: at }),
    ];
    vi.mocked(WebhookDelivery.findAll).mockResolvedValue(rows);

    const page = await listDeliveries({
      limit: 2,
      endpointId: '11111111-1111-4111-8111-111111111111',
      status: 'dead',
      eventType: 'user.created',
    });

    expect(page.deliveries.map((d: any) => d.id)).toEqual(['c', 'b']);
    expect(page.nextCursor).not.toBeNull();

    vi.mocked(WebhookDelivery.findAll).mockResolvedValue([rows[2]]);
    const next = await listDeliveries({ limit: 2, cursor: page.nextCursor! });

    expect(next).toMatchObject({ nextCursor: null });
    expect(vi.mocked(WebhookDelivery.findAll).mock.calls[1][0]).toMatchObject({ limit: 3 });
  });

  it('lists with no filters', async () => {
    vi.mocked(WebhookDelivery.findAll).mockResolvedValue([]);

    expect(await listDeliveries({ limit: 50 })).toEqual({ deliveries: [], nextCursor: null });
  });

  it('refuses a cursor it did not issue', async () => {
    await expect(listDeliveries({ limit: 10, cursor: 'garbage' })).rejects.toMatchObject({
      status: 400,
    });
  });

  it('serializes a delivery', () => {
    expect(serializeDelivery(delivery({ nextAttemptAt: null }))).toEqual({
      id: 'delivery-1',
      endpointId: 'endpoint-1',
      eventType: 'user.created',
      status: 'pending',
      attempts: 0,
      nextAttemptAt: null,
      lastAttemptAt: null,
      lastStatusCode: null,
      lastFailure: null,
      createdAt: at.toISOString(),
    });
  });
});

describe('dispatchWebhooks', () => {
  function queries(...answers: unknown[]) {
    for (const answer of answers) query.mockResolvedValueOnce(answer);
  }

  it('does nothing while another replica holds the lock', async () => {
    queries([{ locked: false }]);

    expect(await dispatchWebhooks()).toBe(0);
    expect(query).toHaveBeenCalledTimes(1);
  });

  it('starts the cursor at the newest row instead of replaying history', async () => {
    queries([{ locked: true }], [], [{ head: '42' }], undefined);

    expect(await dispatchWebhooks()).toBe(0);
    expect(query.mock.calls[3][0]).toContain('INSERT INTO public.event_dispatch_cursors');
    expect(query.mock.calls[3][1].replacements).toMatchObject({ head: '42' });
  });

  it('returns at once when no row is past the cursor', async () => {
    queries([{ locked: true }], [{ lastSeq: '42' }], []);

    expect(await dispatchWebhooks()).toBe(0);
    expect(WebhookEndpoint.findAll).not.toHaveBeenCalled();
  });

  it('queues one delivery per subscribed endpoint and advances the cursor', async () => {
    const created = new Date('2026-11-07T11:59:00.000Z');
    queries(
      [{ locked: true }],
      [{ lastSeq: '9' }],
      [
        {
          seq: '10',
          type: 'user_created',
          user_id: 'user-1',
          session_id: null,
          metadata: null,
          created_at: created,
        },
        // Nobody subscribes to sign-ins here.
        {
          seq: '11',
          type: 'session_created',
          user_id: 'user-1',
          session_id: 's',
          metadata: { method: 'passkey' },
          created_at: created,
        },
        // Subscribed, but this row is about an account rather than a passkey.
        {
          seq: '12',
          type: 'registration_success',
          user_id: 'user-1',
          session_id: null,
          metadata: {},
          created_at: created,
        },
      ],
    );
    query.mockResolvedValue(undefined);
    vi.mocked(WebhookEndpoint.findAll).mockResolvedValue([
      endpoint({ id: 'a', eventTypes: ['user.created', 'credential.added'] }),
      endpoint({ id: 'b', eventTypes: ['user.created'] }),
    ]);
    vi.mocked(User.findByPk).mockResolvedValue({ email: 'a@example.com', phone: null } as any);

    expect(await dispatchWebhooks()).toBe(3);

    const inserts = query.mock.calls.filter(([sql]) =>
      sql.includes('INSERT INTO public.webhook_deliveries'),
    );
    expect(inserts).toHaveLength(2);
    expect(inserts.map(([, options]) => options.replacements.endpointId)).toEqual(['a', 'b']);
    const payload = JSON.parse(inserts[0][1].replacements.payload);
    expect(payload).toEqual({
      id: inserts[0][1].replacements.id,
      type: 'user.created',
      version: 1,
      timestamp: created.toISOString(),
      data: { userId: 'user-1', email: 'a@example.com', phone: null },
    });
    expect(inserts[0][0]).toContain('ON CONFLICT ("endpointId", "authEventSeq") DO NOTHING');

    const advance = query.mock.calls.at(-1)!;
    expect(advance[0]).toContain('UPDATE public.event_dispatch_cursors');
    expect(advance[1].replacements).toMatchObject({ seq: '12' });
  });

  it('builds user.created without an address once the user is gone', async () => {
    queries(
      [{ locked: true }],
      [{ lastSeq: '9' }],
      [
        {
          seq: '10',
          type: 'user_created',
          user_id: 'u',
          session_id: null,
          metadata: null,
          created_at: at,
        },
      ],
    );
    query.mockResolvedValue(undefined);
    vi.mocked(WebhookEndpoint.findAll).mockResolvedValue([endpoint()]);
    vi.mocked(User.findByPk).mockResolvedValue(null);

    await dispatchWebhooks();

    const insert = query.mock.calls.find(([sql]) => sql.includes('webhook_deliveries'))!;
    expect(JSON.parse(insert[1].replacements.payload).data.email).toBeNull();
  });

  it('reads no user for an event that does not carry an address', async () => {
    queries(
      [{ locked: true }],
      [{ lastSeq: '9' }],
      [
        {
          seq: '10',
          type: 'user_deleted',
          user_id: 'u',
          session_id: null,
          metadata: null,
          created_at: at,
        },
      ],
    );
    query.mockResolvedValue(undefined);
    vi.mocked(WebhookEndpoint.findAll).mockResolvedValue([
      endpoint({ eventTypes: ['user.deleted'] }),
    ]);

    await dispatchWebhooks();

    expect(User.findByPk).not.toHaveBeenCalled();
  });
});

describe('deliverDue', () => {
  it('returns at once when nothing is due', async () => {
    query.mockResolvedValueOnce([]);

    expect(await deliverDue()).toBe(0);
    expect(WebhookDelivery.update).not.toHaveBeenCalled();
  });

  it('leases the claimed rows, then sends each to its endpoint', async () => {
    responds(200);
    query.mockResolvedValueOnce([{ id: 'd1' }, { id: 'd2' }]);
    const first = delivery({ id: 'd1' });
    const second = delivery({ id: 'd2', endpointId: 'gone' });
    vi.mocked(WebhookDelivery.findAll).mockResolvedValue([first, second]);
    vi.mocked(WebhookEndpoint.findAll).mockResolvedValue([endpoint()]);

    expect(await deliverDue()).toBe(2);

    expect(query.mock.calls[0][0]).toContain('FOR UPDATE SKIP LOCKED');
    expect(vi.mocked(WebhookDelivery.update).mock.calls[0][0]).toHaveProperty('nextAttemptAt');
    expect(first.status).toBe('succeeded');
    // Its endpoint was deleted or disabled after it was queued: held, not sent.
    expect(second.nextAttemptAt).toBeNull();
    expect(calloutRequest).toHaveBeenCalledTimes(1);
  });
});

describe('the delivery loop', () => {
  it('prunes deliveries older than 30 days', async () => {
    vi.mocked(WebhookDelivery.destroy).mockResolvedValue(3 as never);

    expect(await pruneDeliveries(at)).toBe(3);
    const where = vi.mocked(WebhookDelivery.destroy).mock.calls[0][0] as any;
    const [op] = Object.getOwnPropertySymbols(where.where.createdAt);
    const cutoff = where.where.createdAt[op] as Date;
    expect(cutoff.toISOString()).toBe('2026-10-08T12:00:00.000Z');
  });

  it('runs dispatch and delivery until each comes back short, and prunes on the hour', async () => {
    query.mockImplementation(async (sql: string) =>
      sql.includes('pg_try_advisory_xact_lock') ? [{ locked: false }] : [],
    );
    vi.mocked(WebhookDelivery.destroy).mockResolvedValue(0 as never);

    await runWebhookTick(0);
    expect(WebhookDelivery.destroy).toHaveBeenCalledTimes(1);

    await runWebhookTick(1);
    expect(WebhookDelivery.destroy).toHaveBeenCalledTimes(1);
  });

  it('keeps going after a failed tick', async () => {
    transaction.mockRejectedValue(new Error('database down'));

    await expect(runWebhookTick(1)).resolves.toBeUndefined();
  });

  it('polls once a second and skips a tick while one is running', async () => {
    vi.useFakeTimers();
    let release: () => void = () => {};
    transaction.mockImplementation(
      () => new Promise((resolve) => (release = () => resolve(0))) as never,
    );

    const timer = startWebhookDelivery();
    await vi.advanceTimersByTimeAsync(1000);
    await vi.advanceTimersByTimeAsync(1000);
    expect(transaction).toHaveBeenCalledTimes(1);

    release();
    clearInterval(timer);
  });
});
