import { createHmac } from 'node:crypto';

import { LoginHookCallSchema } from '@seamless-auth/types';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/lib/calloutTransport.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/lib/calloutTransport.js')>();
  return { ...actual, calloutRequest: vi.fn() };
});

vi.mock('../../../src/services/organizationService.js', () => ({
  findMembership: vi.fn(),
}));

import { encryptCalloutSecret } from '../../../src/lib/calloutSigning.js';
import { CalloutError, calloutRequest } from '../../../src/lib/calloutTransport.js';
import { LoginHookInvocation } from '../../../src/models/loginHookInvocations.js';
import { LoginHook } from '../../../src/models/loginHooks.js';
import { AuthEventService } from '../../../src/services/authEventService.js';
import {
  deleteLoginHook,
  getLoginHook,
  listInvocations,
  listLoginHooks,
  LoginHookError,
  loginHookRefusal,
  pruneLoginHookInvocations,
  rotateLoginHookSecret,
  runLoginHook,
  screenHookClaims,
  sendTestCall,
  serializeInvocation,
  serializeLoginHook,
  setLoginHook,
  startLoginHookMaintenance,
  verdictClaims,
} from '../../../src/services/loginHookService.js';
import { findMembership } from '../../../src/services/organizationService.js';

const at = new Date('2026-11-07T12:00:00.000Z');
const secret = 'whsec_' + Buffer.alloc(32, 7).toString('base64');
const previous = 'whsec_' + Buffer.alloc(32, 9).toString('base64');

function hook(overrides: Record<string, unknown> = {}) {
  const sealed = encryptCalloutSecret(secret);
  const record: any = {
    trigger: 'post_login',
    url: 'https://hooks.example.com/login?token=abc',
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
    createdAt: at,
    updatedAt: at,
    ...overrides,
  };
  record.update = vi.fn(async (changes: Record<string, unknown>) => Object.assign(record, changes));
  record.destroy = vi.fn();
  return record;
}

function req(headers: Record<string, string> = {}) {
  const all: Record<string, string> = {
    'user-agent': 'test-agent',
    authorization: 'Bearer secret-access-token',
    cookie: 'seamless-refresh=secret-refresh-token',
    ...headers,
  };
  return { ip: '203.0.113.9', get: (name: string) => all[name.toLowerCase()] } as any;
}

const user = { id: 'user-1', email: 'a@example.com', phone: null, roles: ['user'] };

function context(overrides: Record<string, unknown> = {}) {
  return { user, method: 'passkey', organizationId: null, req: req(), ...overrides } as any;
}

function answer(status: number, body: unknown) {
  vi.mocked(calloutRequest).mockResolvedValueOnce({
    status,
    headers: {},
    body: Buffer.from(typeof body === 'string' ? body : JSON.stringify(body)),
  });
}

function sent() {
  const [url, options] = vi.mocked(calloutRequest).mock.calls[0];
  return { url, options, body: JSON.parse(options.body as string) };
}

function audited(type: string) {
  return vi.mocked(AuthEventService.log).mock.calls.filter(([event]) => event.type === type);
}

beforeEach(() => {
  vi.mocked(LoginHook.findByPk).mockResolvedValue(hook() as any);
});

afterEach(() => {
  vi.useRealTimers();
});

describe('runLoginHook', () => {
  it('skips a trigger with no hook, or one turned off, without calling anything', async () => {
    vi.mocked(LoginHook.findByPk).mockResolvedValueOnce(null);
    expect(await runLoginHook('post_login', context())).toEqual({ outcome: 'skipped' });

    vi.mocked(LoginHook.findByPk).mockResolvedValueOnce(hook({ enabled: false }) as any);
    expect(await runLoginHook('post_login', context())).toEqual({ outcome: 'skipped' });

    expect(calloutRequest).not.toHaveBeenCalled();
    expect(LoginHookInvocation.create).not.toHaveBeenCalled();
  });

  it('sends only the published call shape: no token, code, cookie or secret', async () => {
    answer(200, { decision: 'allow' });

    await runLoginHook(
      'post_login',
      context({
        user: {
          ...user,
          refreshToken: 'secret-refresh-token',
          totpSecret: 'JBSWY3DPEHPK3PXP',
          passwordHash: 'x',
        },
        req: req({ 'x-verification-code': '123456' }),
      }),
    );

    const { url, options, body } = sent();
    expect(url).toBe('https://hooks.example.com/login?token=abc');
    expect(LoginHookCallSchema.strict().safeParse(body).success).toBe(true);
    expect(Object.keys(body).sort()).toEqual(
      ['client', 'id', 'method', 'organization', 'request', 'timestamp', 'trigger', 'user'].sort(),
    );
    expect(Object.keys(body.user).sort()).toEqual(['email', 'id', 'phone', 'roles']);
    expect(body.request).toEqual({ ipAddress: '203.0.113.9', userAgent: 'test-agent' });

    const raw = options.body as string;
    for (const leaked of [
      'secret-access-token',
      'secret-refresh-token',
      'JBSWY3DPEHPK3PXP',
      '123456',
      secret,
      secret.slice('whsec_'.length),
    ]) {
      expect(raw).not.toContain(leaked);
    }
  });

  it('signs the call with Standard Webhooks headers, using the invocation id as webhook-id', async () => {
    answer(200, { decision: 'allow' });

    await runLoginHook('post_login', context());

    const { options, body } = sent();
    const headers = options.headers as Record<string, string>;
    expect(headers['webhook-id']).toBe(body.id);
    const expected = createHmac('sha256', Buffer.from(secret.slice(6), 'base64'))
      .update(`${body.id}.${headers['webhook-timestamp']}.${options.body}`)
      .digest('base64');
    expect(headers['webhook-signature']).toBe(`v1,${expected}`);
    expect(options.timeoutMs).toBe(2000);
    expect(LoginHookInvocation.create).toHaveBeenCalledWith(
      expect.objectContaining({ id: body.id, trigger: 'post_login', outcome: 'allowed' }),
    );
  });

  it('signs with both secrets while one rotates out', async () => {
    const old = encryptCalloutSecret(previous);
    vi.mocked(LoginHook.findByPk).mockResolvedValueOnce(
      hook({
        previousSecretCiphertext: old.ciphertext,
        previousSecretIv: old.iv,
        previousSecretTag: old.tag,
        previousSecretExpiresAt: new Date(Date.now() + 60_000),
      }) as any,
    );
    answer(200, { decision: 'allow' });

    await runLoginHook('post_login', context());

    const headers = sent().options.headers as Record<string, string>;
    expect(headers['webhook-signature'].split(' ')).toHaveLength(2);
  });

  it('carries the organization and its roles, read when not given', async () => {
    vi.mocked(findMembership).mockResolvedValueOnce({ roles: ['admin'] } as any);
    answer(200, { decision: 'allow' });
    await runLoginHook('post_login', context({ organizationId: 'org-1' }));
    expect(sent().body.organization).toEqual({ id: 'org-1', roles: ['admin'] });

    vi.mocked(calloutRequest).mockClear();
    vi.mocked(findMembership).mockResolvedValueOnce(null);
    answer(200, { decision: 'allow' });
    await runLoginHook('post_login', context({ organizationId: 'org-2' }));
    expect(sent().body.organization).toEqual({ id: 'org-2', roles: [] });

    vi.mocked(calloutRequest).mockClear();
    answer(200, { decision: 'allow' });
    await runLoginHook(
      'post_login',
      context({ organizationId: 'org-3', organizationRoles: ['member'] }),
    );
    expect(sent().body.organization).toEqual({ id: 'org-3', roles: ['member'] });
  });

  it('allows, and audits the success', async () => {
    answer(204, '{"decision":"allow"}');

    expect(await runLoginHook('post_login', context())).toEqual({
      outcome: 'allowed',
      claims: null,
    });
    expect(audited('login_hook_success')).toHaveLength(1);
  });

  it('denies with the userMessage and audits the reason, which is never shown', async () => {
    answer(200, { decision: 'deny', reason: 'internal: tenant suspended', userMessage: 'Ask IT' });

    const verdict = await runLoginHook('post_login', context());

    expect(verdict).toEqual({ outcome: 'denied', userMessage: 'Ask IT' });
    expect(loginHookRefusal(verdict)).toEqual({
      status: 403,
      body: { error: 'login_denied', message: 'Ask IT' },
    });
    expect(JSON.stringify(loginHookRefusal(verdict))).not.toContain('tenant suspended');
    expect(audited('login_hook_denied')[0][0].metadata).toMatchObject({
      reason: 'internal: tenant suspended',
    });
    expect(LoginHookInvocation.create).toHaveBeenCalledWith(
      expect.objectContaining({ outcome: 'denied', statusCode: 200 }),
    );
  });

  it('denies with no message when the hook gives none', async () => {
    answer(200, { decision: 'deny' });

    const verdict = await runLoginHook('post_login', context());

    expect(loginHookRefusal(verdict)).toEqual({ status: 403, body: { error: 'login_denied' } });
    expect(audited('login_hook_denied')[0][0].metadata).not.toHaveProperty('reason');
  });

  it.each([
    [
      'a timeout',
      () => vi.mocked(calloutRequest).mockRejectedValueOnce(new CalloutError('timed_out', 'x')),
      'timed_out',
      null,
    ],
    [
      'a refused address',
      () => vi.mocked(calloutRequest).mockRejectedValueOnce(new CalloutError('refused', 'x')),
      'refused',
      null,
    ],
    [
      'an unexpected error',
      () => vi.mocked(calloutRequest).mockRejectedValueOnce(new Error('boom')),
      'connection_failed',
      null,
    ],
    ['a 500', () => answer(500, { decision: 'allow' }), 'http_status', 500],
    ['a redirect, which is not followed', () => answer(302, ''), 'http_status', 302],
    ['a body that is not JSON', () => answer(200, 'allow'), 'invalid_response', 200],
    ['a body without a decision', () => answer(200, { ok: true }), 'invalid_response', 200],
    [
      'claims from post_login, which may not add any',
      () => answer(200, { decision: 'allow', claims: { plan: 'pro' } }),
      'invalid_response',
      200,
    ],
  ])('fails closed on %s', async (_name, arrange, failure, statusCode) => {
    arrange();

    const verdict = await runLoginHook('post_login', context());

    expect(verdict).toEqual({ outcome: 'failed_closed' });
    expect(loginHookRefusal(verdict)).toEqual({
      status: 503,
      body: { error: 'login_hook_unavailable' },
    });
    expect(LoginHookInvocation.create).toHaveBeenCalledWith(
      expect.objectContaining({ outcome: 'failed_closed', failure, statusCode }),
    );
    expect(audited('login_hook_failed')[0][0].metadata).toMatchObject({
      failure,
      failureMode: 'closed',
    });
  });

  it('continues without the hook when it fails open', async () => {
    vi.mocked(LoginHook.findByPk).mockResolvedValueOnce(hook({ failureMode: 'open' }) as any);
    vi.mocked(calloutRequest).mockRejectedValueOnce(new CalloutError('timed_out', 'x'));

    const verdict = await runLoginHook('post_login', context());

    expect(verdict).toEqual({ outcome: 'failed_open' });
    expect(loginHookRefusal(verdict)).toBeNull();
    expect(verdictClaims(verdict)).toBeNull();
  });

  it('fails when a stored secret no longer decrypts', async () => {
    vi.mocked(LoginHook.findByPk).mockResolvedValueOnce(hook({ secretTag: 'AAAA' }) as any);

    expect(await runLoginHook('post_login', context())).toEqual({ outcome: 'failed_closed' });
    expect(calloutRequest).not.toHaveBeenCalled();
  });

  it('does not swallow a failure to record the invocation', async () => {
    answer(200, { decision: 'allow' });
    vi.mocked(LoginHookInvocation.create).mockRejectedValueOnce(new Error('db down'));

    await expect(runLoginHook('post_login', context())).rejects.toThrow('db down');
  });

  describe('pre_token', () => {
    beforeEach(() => {
      vi.mocked(LoginHook.findByPk).mockResolvedValue(hook({ trigger: 'pre_token' }) as any);
    });

    it('returns the claims', async () => {
      answer(200, { decision: 'allow', claims: { plan: 'pro', tier: { level: 2 } } });

      const verdict = await runLoginHook('pre_token', context());

      expect(verdictClaims(verdict)).toEqual({ plan: 'pro', tier: { level: 2 } });
      expect(audited('login_hook_success')[0][0].metadata).toMatchObject({
        claimNames: ['plan', 'tier'],
      });
    });

    it('allows with no claims as an empty set', async () => {
      answer(200, { decision: 'allow' });
      expect(verdictClaims(await runLoginHook('pre_token', context()))).toEqual({});
    });

    it('strips reserved names, and audits which', async () => {
      answer(200, {
        decision: 'allow',
        claims: {
          sub: 'someone-else',
          email: 'ceo@example.com',
          org_id: 'x',
          seamless_x: 1,
          plan: 'pro',
        },
      });

      const verdict = await runLoginHook('pre_token', context());

      expect(verdictClaims(verdict)).toEqual({ plan: 'pro' });
      expect(audited('login_hook_claims_stripped')[0][0].metadata).toMatchObject({
        names: ['sub', 'email', 'org_id', 'seamless_x'],
      });
    });

    it('ignores claims on a deny', async () => {
      answer(200, { decision: 'deny', claims: { plan: 'pro' } });
      expect(await runLoginHook('pre_token', context())).toEqual({
        outcome: 'denied',
        userMessage: null,
      });
    });

    it.each([
      ['over the 1 KiB budget', { big: 'x'.repeat(1100) }, 'too_large'],
      ['with a name outside the claim alphabet', { Plan: 'pro' }, 'invalid_response'],
      ['nested deeper than 3', { deep: { a: { b: { c: { d: 1 } } } } }, 'invalid_response'],
    ])('fails a hook whose claims are %s', async (_name, claims, failure) => {
      answer(200, { decision: 'allow', claims });

      expect(await runLoginHook('pre_token', context())).toEqual({ outcome: 'failed_closed' });
      expect(LoginHookInvocation.create).toHaveBeenCalledWith(
        expect.objectContaining({ failure, statusCode: 200 }),
      );
    });

    it('fails a body that does not parse', async () => {
      answer(200, { decision: 'maybe' });
      expect(await runLoginHook('pre_token', context())).toEqual({ outcome: 'failed_closed' });
    });
  });
});

describe('screenHookClaims', () => {
  it('keeps a set exactly at the budget', () => {
    const value = 'x'.repeat(1024 - '{"a":""}'.length);
    expect(screenHookClaims({ a: value }).kept).toEqual({ a: value });
  });
});

describe('admin', () => {
  it('serializes a hook without its secret, and shows the overlap only while it lasts', () => {
    const serialized = serializeLoginHook(
      hook({ previousSecretExpiresAt: new Date(Date.now() + 1000) }) as any,
    );
    expect(serialized).not.toHaveProperty('secretCiphertext');
    expect(serialized.previousSecretExpiresAt).not.toBeNull();
    expect(
      serializeLoginHook(hook({ previousSecretExpiresAt: new Date(0) }) as any)
        .previousSecretExpiresAt,
    ).toBeNull();
  });

  it('serializes an invocation', () => {
    expect(
      serializeInvocation({
        id: 'i',
        trigger: 'pre_token',
        userId: null,
        outcome: 'allowed',
        failure: null,
        statusCode: null,
        durationMs: 3,
        createdAt: at,
      } as any),
    ).toEqual({
      id: 'i',
      trigger: 'pre_token',
      userId: null,
      outcome: 'allowed',
      failure: null,
      statusCode: null,
      durationMs: 3,
      createdAt: at.toISOString(),
    });
  });

  it('lists and gets hooks', async () => {
    vi.mocked(LoginHook.findAll).mockResolvedValueOnce([hook()] as any);
    expect(await listLoginHooks()).toHaveLength(1);

    vi.mocked(LoginHook.findByPk).mockResolvedValueOnce(null);
    await expect(getLoginHook('pre_token')).rejects.toMatchObject({ status: 404 });
  });

  it('creates a hook with a fresh secret', async () => {
    vi.mocked(LoginHook.findByPk).mockResolvedValueOnce(null);
    vi.mocked(LoginHook.create).mockImplementationOnce(async (values: any) => values);

    const result = await setLoginHook(
      'post_login',
      { url: 'https://hooks.example.com/a', timeoutMs: 1500, failureMode: 'open', enabled: true },
      'admin-1',
    );

    expect(result.created).toBe(true);
    expect(result.secret).toMatch(/^whsec_/);
    expect(LoginHook.create).toHaveBeenCalledWith(
      expect.objectContaining({ trigger: 'post_login', timeoutMs: 1500, createdBy: 'admin-1' }),
    );
  });

  it('replaces settings and keeps the secret', async () => {
    const existing = hook();
    vi.mocked(LoginHook.findByPk).mockResolvedValueOnce(existing as any);

    const result = await setLoginHook(
      'post_login',
      {
        url: 'https://hooks.example.com/b',
        timeoutMs: 2000,
        failureMode: 'closed',
        enabled: false,
      },
      null,
    );

    expect(result).toMatchObject({ created: false, secret: undefined });
    expect(existing.update).toHaveBeenCalledWith({
      url: 'https://hooks.example.com/b',
      timeoutMs: 2000,
      failureMode: 'closed',
      enabled: false,
    });
  });

  it('refuses a URL no callout may reach', async () => {
    await expect(
      setLoginHook(
        'post_login',
        { url: 'http://169.254.169.254/', timeoutMs: 2000, failureMode: 'closed', enabled: true },
        null,
      ),
    ).rejects.toMatchObject({ status: 400 });
  });

  it('refuses to create or rotate in production without the encryption key', async () => {
    vi.stubEnv('NODE_ENV', 'production');
    vi.stubEnv('CALLOUT_SECRET_ENCRYPTION_KEY', '');
    vi.mocked(LoginHook.findByPk).mockResolvedValueOnce(null);

    await expect(
      setLoginHook(
        'post_login',
        {
          url: 'https://hooks.example.com/a',
          timeoutMs: 2000,
          failureMode: 'closed',
          enabled: true,
        },
        null,
      ),
    ).rejects.toBeInstanceOf(LoginHookError);
    await expect(rotateLoginHookSecret('post_login')).rejects.toMatchObject({ status: 409 });
    expect(LoginHook.create).not.toHaveBeenCalled();
  });

  it('rotates, keeping the old secret signing for a day', async () => {
    const existing = hook();
    const oldCiphertext = existing.secretCiphertext;
    vi.mocked(LoginHook.findByPk).mockResolvedValueOnce(existing as any);

    const { secret: next, previousSecretExpiresAt } = await rotateLoginHookSecret('post_login');

    expect(next).toMatch(/^whsec_/);
    expect(previousSecretExpiresAt.getTime() - Date.now()).toBeGreaterThan(23 * 3600 * 1000);
    expect(existing.update).toHaveBeenCalledWith(
      expect.objectContaining({ previousSecretCiphertext: oldCiphertext }),
    );
  });

  it('deletes', async () => {
    const existing = hook();
    vi.mocked(LoginHook.findByPk).mockResolvedValueOnce(existing as any);
    await deleteLoginHook('post_login');
    expect(existing.destroy).toHaveBeenCalled();
  });

  it('lists invocations newest first, optionally by outcome', async () => {
    await listInvocations('pre_token', { limit: 10, outcome: 'denied' });
    expect(LoginHookInvocation.findAll).toHaveBeenLastCalledWith({
      where: { trigger: 'pre_token', outcome: 'denied' },
      order: [['createdAt', 'DESC']],
      limit: 10,
    });

    await listInvocations('pre_token', { limit: 5 });
    expect(LoginHookInvocation.findAll).toHaveBeenLastCalledWith(
      expect.objectContaining({ where: { trigger: 'pre_token' } }),
    );
  });

  it('prunes invocations older than 30 days', async () => {
    await pruneLoginHookInvocations(at);
    const where = vi.mocked(LoginHookInvocation.destroy).mock.calls[0][0]!.where as any;
    const cutoff = Object.getOwnPropertySymbols(where.createdAt).map((s) => where.createdAt[s])[0];
    expect(cutoff).toEqual(new Date('2026-10-08T12:00:00.000Z'));
  });

  it('prunes hourly and logs a failure rather than throwing', async () => {
    vi.useFakeTimers();
    vi.mocked(LoginHookInvocation.destroy).mockRejectedValueOnce(new Error('db down'));

    const timer = startLoginHookMaintenance();
    await vi.advanceTimersByTimeAsync(60 * 60 * 1000);
    await vi.advanceTimersByTimeAsync(60 * 60 * 1000);
    clearInterval(timer);

    expect(LoginHookInvocation.destroy).toHaveBeenCalledTimes(2);
  });

  it('sends a test call with a placeholder user and no request details', async () => {
    answer(200, { decision: 'allow' });

    const result = await sendTestCall('post_login');

    expect(result).toMatchObject({ ok: true, failure: null, statusCode: 200 });
    const { body } = sent();
    expect(body.user).toEqual({
      id: '00000000-0000-4000-8000-000000000000',
      email: null,
      phone: null,
      roles: [],
    });
    expect(body.request).toEqual({ ipAddress: null, userAgent: null });
    expect(LoginHookInvocation.create).not.toHaveBeenCalled();
  });

  it('reports a failed test call', async () => {
    answer(500, '');
    expect(await sendTestCall('post_login')).toMatchObject({
      ok: false,
      failure: 'http_status',
      statusCode: 500,
    });
  });

  it('lets an unexpected error from a test call through', async () => {
    vi.mocked(LoginHook.findByPk).mockResolvedValueOnce(null);
    await expect(sendTestCall('post_login')).rejects.toMatchObject({ status: 404 });
  });
});
