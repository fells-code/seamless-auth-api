import { Application } from 'express';
import request from 'supertest';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/lib/calloutTransport.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/lib/calloutTransport.js')>();
  return { ...actual, calloutRequest: vi.fn() };
});

import { createApp } from '../../../src/app';
import { encryptCalloutSecret } from '../../../src/lib/calloutSigning.js';
import { calloutRequest } from '../../../src/lib/calloutTransport.js';
import { LoginHookInvocation } from '../../../src/models/loginHookInvocations.js';
import { LoginHook } from '../../../src/models/loginHooks.js';
import { Session } from '../../../src/models/sessions.js';
import { AuthEventService } from '../../../src/services/authEventService.js';
import { buildFreshStepUpSession } from '../../factories/sessionFactory';

let app: Application;

const now = new Date('2026-11-07T12:00:00.000Z');

function buildHook(overrides: Record<string, unknown> = {}) {
  const sealed = encryptCalloutSecret('whsec_' + Buffer.alloc(32, 3).toString('base64'));
  const record: any = {
    trigger: 'pre_token',
    url: 'https://hooks.example.com/claims',
    timeoutMs: 2000,
    failureMode: 'closed',
    enabled: true,
    secretCiphertext: sealed.ciphertext,
    secretIv: sealed.iv,
    secretTag: sealed.tag,
    previousSecretCiphertext: null,
    previousSecretIv: null,
    previousSecretTag: null,
    previousSecretExpiresAt: null,
    createdBy: null,
    createdAt: now,
    updatedAt: now,
    ...overrides,
  };
  record.update = vi.fn(async (values: Record<string, unknown>) => Object.assign(record, values));
  record.destroy = vi.fn();
  return record;
}

function auditTypes() {
  return vi.mocked(AuthEventService.log).mock.calls.map(([options]) => options.type);
}

beforeAll(async () => {
  app = await createApp();
});

beforeEach(() => {
  vi.clearAllMocks();
  (Session.findOne as any).mockResolvedValue(buildFreshStepUpSession());
});

describe('login hooks admin', () => {
  it('lists hooks without their secrets', async () => {
    vi.mocked(LoginHook.findAll).mockResolvedValue([buildHook()]);

    const res = await request(app).get('/admin/login-hooks');

    expect(res.status).toBe(200);
    expect(res.body.hooks[0]).toMatchObject({ trigger: 'pre_token', failureMode: 'closed' });
    expect(JSON.stringify(res.body)).not.toMatch(/secret(Ciphertext|Iv|Tag)|whsec_/);
  });

  it('creates a hook with the defaults, returns the secret once and audits without the query', async () => {
    vi.mocked(LoginHook.findByPk).mockResolvedValue(null);
    vi.mocked(LoginHook.create).mockImplementation(async (values: any) => buildHook(values));

    const res = await request(app)
      .put('/admin/login-hooks/post_login')
      .send({ url: 'https://hooks.example.com/a?token=abc' });

    expect(res.status).toBe(201);
    expect(res.body.secret).toMatch(/^whsec_/);
    expect(res.body.hook).toMatchObject({
      trigger: 'post_login',
      timeoutMs: 2000,
      failureMode: 'closed',
      enabled: true,
    });
    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'admin_login_hook_set',
        metadata: expect.objectContaining({ url: 'https://hooks.example.com/a', created: true }),
      }),
    );
  });

  it('replaces a hook without handing out its secret again', async () => {
    vi.mocked(LoginHook.findByPk).mockResolvedValue(buildHook());

    const res = await request(app)
      .put('/admin/login-hooks/pre_token')
      .send({ url: 'https://hooks.example.com/b', timeoutMs: 5000, failureMode: 'open' });

    expect(res.status).toBe(200);
    expect(res.body).not.toHaveProperty('secret');
    expect(res.body.hook).toMatchObject({ timeoutMs: 5000, failureMode: 'open' });
  });

  it.each([
    ['an unknown trigger', '/admin/login-hooks/pre_refresh', { url: 'https://hooks.example.com' }],
    [
      'a timeout over 5 seconds',
      '/admin/login-hooks/pre_token',
      { url: 'https://hooks.example.com', timeoutMs: 5001 },
    ],
    [
      'the cloud metadata address',
      '/admin/login-hooks/pre_token',
      { url: 'http://169.254.169.254/latest' },
    ],
  ])('refuses %s', async (_name, path, body) => {
    vi.mocked(LoginHook.findByPk).mockResolvedValue(null);

    const res = await request(app).put(path).send(body);

    expect(res.status).toBe(400);
    expect(LoginHook.create).not.toHaveBeenCalled();
  });

  it('refuses to create a hook in production without the encryption key', async () => {
    vi.stubEnv('NODE_ENV', 'production');
    vi.stubEnv('CALLOUT_SECRET_ENCRYPTION_KEY', '');
    vi.mocked(LoginHook.findByPk).mockResolvedValue(null);

    const res = await request(app)
      .put('/admin/login-hooks/pre_token')
      .send({ url: 'https://hooks.example.com/a' });

    expect(res.status).toBe(409);
    expect(LoginHook.create).not.toHaveBeenCalled();
  });

  it('reads, rotates and deletes, auditing each write', async () => {
    const record = buildHook();
    vi.mocked(LoginHook.findByPk).mockResolvedValue(record);

    expect((await request(app).get('/admin/login-hooks/pre_token')).status).toBe(200);

    const rotated = await request(app).post('/admin/login-hooks/pre_token/secret');
    expect(rotated.status).toBe(200);
    expect(rotated.body.secret).toMatch(/^whsec_/);
    expect(rotated.body.previousSecretExpiresAt).toBeDefined();

    const deleted = await request(app).delete('/admin/login-hooks/pre_token');
    expect(deleted.status).toBe(200);
    expect(record.destroy).toHaveBeenCalled();

    expect(auditTypes()).toEqual(['admin_login_hook_secret_rotated', 'admin_login_hook_deleted']);
  });

  it('answers 404 for a trigger with no hook', async () => {
    vi.mocked(LoginHook.findByPk).mockResolvedValue(null);

    for (const send of [
      () => request(app).get('/admin/login-hooks/pre_token'),
      () => request(app).delete('/admin/login-hooks/pre_token'),
      () => request(app).post('/admin/login-hooks/pre_token/secret'),
      () => request(app).post('/admin/login-hooks/pre_token/test'),
    ]) {
      expect((await send()).status).toBe(404);
    }
  });

  it('sends a test call and reports the result', async () => {
    vi.mocked(LoginHook.findByPk).mockResolvedValue(buildHook());
    vi.mocked(calloutRequest).mockResolvedValue({
      status: 200,
      headers: {},
      body: Buffer.from(JSON.stringify({ decision: 'allow', claims: { plan: 'pro' } })),
    });

    const res = await request(app).post('/admin/login-hooks/pre_token/test');

    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ ok: true, failure: null, statusCode: 200 });
  });

  it('lists invocations', async () => {
    vi.mocked(LoginHookInvocation.findAll).mockResolvedValue([
      {
        id: '7d0c3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f',
        trigger: 'pre_token',
        userId: null,
        outcome: 'failed_closed',
        failure: 'timed_out',
        statusCode: null,
        durationMs: 2000,
        createdAt: now,
      } as any,
    ]);

    const res = await request(app).get(
      '/admin/login-hooks/pre_token/invocations?outcome=failed_closed&limit=5',
    );

    expect(res.status).toBe(200);
    expect(res.body.invocations[0]).toMatchObject({
      outcome: 'failed_closed',
      failure: 'timed_out',
    });
    expect(LoginHookInvocation.findAll).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { trigger: 'pre_token', outcome: 'failed_closed' },
        limit: 5,
      }),
    );
  });
});
