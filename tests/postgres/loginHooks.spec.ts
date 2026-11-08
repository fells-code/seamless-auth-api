import { randomUUID } from 'crypto';
import fs from 'fs';
import { decodeJwt } from 'jose';
import os from 'os';
import path from 'path';
import request from 'supertest';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { invalidateSystemConfigCache } from '../../src/config/getSystemConfig.js';
import { getSequelize, initializeModels } from '../../src/models/index.js';
import { LoginHookInvocation } from '../../src/models/loginHookInvocations.js';
import { Session } from '../../src/models/sessions.js';
import { SystemConfig } from '../../src/models/systemConfig.js';
import { User } from '../../src/models/users.js';
import { startHookServer } from '../factories/loginHookFactory.js';
import { buildSystemConfig } from '../factories/systemConfigFactory.js';

type App = Awaited<ReturnType<typeof import('../../src/app.js').createApp>>;
type Tokens = typeof import('../../src/lib/token.js');
type Hooks = typeof import('../../src/services/loginHookService.js');
type Issuance = typeof import('../../src/services/sessionIssuance.js');

let app: App;
let tokens: Tokens;
let hooks: Hooks;
let issuance: Issuance;
const savedEnv: Record<string, string | undefined> = {};

function setEnv(values: Record<string, string>) {
  for (const [key, value] of Object.entries(values)) {
    savedEnv[key] = process.env[key];
    process.env[key] = value;
  }
}

beforeAll(async () => {
  setEnv({
    ISSUER: 'http://localhost:5312',
    DISABLE_AUTH_RATE_LIMITS: 'true',
    SEAMLESS_DEV_KEYS_DIR: fs.mkdtempSync(path.join(os.tmpdir(), 'seamless-keys-')),
  });

  await initializeModels();

  for (const [key, value] of Object.entries(buildSystemConfig())) {
    await getSequelize().query(
      `INSERT INTO system_config (key, value, "createdAt", "updatedAt")
       VALUES (:key, CAST(:value AS jsonb), now(), now())
       ON CONFLICT (key) DO NOTHING`,
      { replacements: { key, value: JSON.stringify(value) } },
    );
  }
  await getSequelize().query(
    `INSERT INTO system_config (key, value, "createdAt", "updatedAt")
     VALUES ('max_concurrent_sessions', 'null'::jsonb, now(), now())
     ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
  );
  invalidateSystemConfigCache();

  // After ISSUER is set, which the token module reads when it loads.
  tokens = await import('../../src/lib/token.js');
  hooks = await import('../../src/services/loginHookService.js');
  issuance = await import('../../src/services/sessionIssuance.js');

  const { initDevSigningKey } = await import('../../src/utils/signingKeyStore.js');
  const { createApp } = await import('../../src/app.js');
  initDevSigningKey();
  app = await createApp();
});

beforeEach(async () => {
  await getSequelize().query('DELETE FROM login_hook_invocations; DELETE FROM login_hooks;');
  invalidateSystemConfigCache();
});

afterAll(async () => {
  await getSequelize().query('DELETE FROM login_hook_invocations; DELETE FROM login_hooks;');
  await SystemConfig.destroy({ where: { key: ['max_concurrent_sessions'] } });
  await getSequelize().query(`DELETE FROM users WHERE email LIKE :pattern`, {
    replacements: { pattern: '%@login-hooks.test' },
  });
  invalidateSystemConfigCache();
  for (const [key, value] of Object.entries(savedEnv)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  await getSequelize().close();
});

function createUser() {
  return User.create({
    email: `${randomUUID()}@login-hooks.test`,
    phone: null,
    roles: ['user'],
  } as never);
}

function fakeResponse() {
  const res: any = { body: undefined, statusCode: 200 };
  res.status = (code: number) => {
    res.statusCode = code;
    return res;
  };
  res.json = (body: unknown) => {
    res.body = body;
    return res;
  };
  return res;
}

const fakeRequest = {
  ip: '127.0.0.1',
  headers: { 'user-agent': 'login-hooks-test' },
  get: () => 'login-hooks-test',
} as never;

describe('pre_token claims on the session', () => {
  it('are stored at sign-in and survive refresh, which never calls the hook', async () => {
    const hook = await startHookServer(200, {
      decision: 'allow',
      claims: { plan: 'pro', email: 'spoofed@example.com' },
    });
    try {
      await hooks.setLoginHook(
        'pre_token',
        { url: hook.url, timeoutMs: 2000, failureMode: 'closed', enabled: true },
        null,
      );
      const user = await createUser();
      const res = fakeResponse();

      expect(
        await issuance.issueSessionAndRespond({
          method: 'passkey',
          user: { id: user.id, email: user.email, phone: null, roles: ['user'] },
          req: fakeRequest,
          res,
        }),
      ).toBe(true);

      expect(hook.received).toHaveLength(1);
      expect(decodeJwt(res.body.token).plan).toBe('pro');
      expect(decodeJwt(res.body.token).email).toBeUndefined();

      const signedIn = await Session.findOne({ where: { userId: user.id } });
      expect(signedIn?.hookClaims).toEqual({ plan: 'pro' });

      const refreshed = await request(app)
        .post('/refresh')
        .set('Authorization', `Bearer ${res.body.refreshToken}`);

      expect(refreshed.status).toBe(200);
      expect(decodeJwt(refreshed.body.token).plan).toBe('pro');
      expect(hook.received).toHaveLength(1);

      const rotated = await Session.findByPk(refreshed.body.sessionId);
      expect(rotated?.hookClaims).toEqual({ plan: 'pro' });
      expect(rotated?.id).not.toBe(signedIn?.id);

      expect(await LoginHookInvocation.count({ where: { userId: user.id } })).toBe(1);
    } finally {
      await hook.close();
    }
  });

  it('round-trips null for a session no hook touched', async () => {
    const user = await createUser();
    const refreshToken = tokens.generateRefreshToken();
    const now = Date.now();
    await Session.create({
      userId: user.id,
      mode: 'server',
      refreshTokenLookup: tokens.createRefreshTokenLookup(refreshToken),
      expiresAt: new Date(now + 3_600_000),
      idleExpiresAt: new Date(now + 3_600_000),
      lastUsedAt: new Date(now),
      chainStartedAt: new Date(now),
    });

    const refreshed = await request(app)
      .post('/refresh')
      .set('Authorization', `Bearer ${refreshToken}`);

    expect(refreshed.status).toBe(200);
    expect((await Session.findByPk(refreshed.body.sessionId))?.hookClaims).toBeNull();
  });
});

describe('login hook invocations', () => {
  it('records a denied post_login and prunes rows older than 30 days', async () => {
    const hook = await startHookServer(200, { decision: 'deny', reason: 'no' });
    try {
      await hooks.setLoginHook(
        'post_login',
        { url: hook.url, timeoutMs: 2000, failureMode: 'closed', enabled: true },
        null,
      );
      const user = await createUser();

      const verdict = await hooks.runLoginHook('post_login', {
        user: { id: user.id, email: user.email, phone: null, roles: ['user'] },
        method: 'passkey',
        organizationId: null,
        req: fakeRequest,
      });
      expect(verdict).toEqual({ outcome: 'denied', userMessage: null });

      const fresh = await LoginHookInvocation.findOne({ where: { userId: user.id } });
      expect(fresh).toMatchObject({ outcome: 'denied', statusCode: 200, trigger: 'post_login' });

      const stale = randomUUID();
      await getSequelize().query(
        `INSERT INTO login_hook_invocations
           (id, trigger, outcome, "durationMs", "createdAt", "updatedAt")
         VALUES (:id, 'post_login', 'allowed', 5, now() - interval '31 days', now())`,
        { replacements: { id: stale } },
      );

      expect(await hooks.pruneLoginHookInvocations()).toBe(1);
      expect(await LoginHookInvocation.findByPk(stale)).toBeNull();
      expect(await LoginHookInvocation.findByPk(fresh!.id)).not.toBeNull();
    } finally {
      await hook.close();
    }
  });

  it('refuses a timeout the table does not allow', async () => {
    await expect(
      getSequelize().query(
        `INSERT INTO login_hooks (trigger, url, "timeoutMs", "secretCiphertext", "secretIv",
           "secretTag", "createdAt", "updatedAt")
         VALUES ('pre_token', 'https://x.example', 6000, 'c', 'i', 't', now(), now())`,
      ),
    ).rejects.toThrow(/login_hooks_timeout/);
  });
});
