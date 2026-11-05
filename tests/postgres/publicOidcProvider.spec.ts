import { generateKeyPairSync, randomUUID } from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import request from 'supertest';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { invalidateSystemConfigCache } from '../../src/config/getSystemConfig.js';
import { AuthEvent } from '../../src/models/authEvents.js';
import { getSequelize, initializeModels } from '../../src/models/index.js';
import { OidcClient, type OidcClientAttributes } from '../../src/models/oidcClients.js';
import { Session } from '../../src/models/sessions.js';
import { SystemConfig } from '../../src/models/systemConfig.js';
import { User } from '../../src/models/users.js';
import { buildSystemConfig } from '../factories/systemConfigFactory.js';

const API_ISSUER = 'http://localhost:5312';
const PROVIDER_ISSUER = 'https://login.public-oidc-provider.test';
const KEYS = ['oidc_provider_enabled', 'oidc_issuer', 'oidc_cli_client_id'];
const WITHOUT_ADVERTISEMENT = ['loginMethods', 'recoveryCodes', 'accountRecovery'];

const CONFIDENTIAL: Partial<OidcClientAttributes> = {
  clientType: 'confidential',
  tokenEndpointAuthMethod: 'private_key_jwt',
  jwksUri: 'https://app.example.com/jwks',
};

const providerKey = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey;

type App = Awaited<ReturnType<typeof import('../../src/app.js').createApp>>;
type Tokens = typeof import('../../src/lib/token.js');

let app: App;
let tokens: Tokens;
const savedEnv: Record<string, string | undefined> = {};

function setEnv(values: Record<string, string>) {
  for (const [key, value] of Object.entries(values)) {
    savedEnv[key] = process.env[key];
    process.env[key] = value;
  }
}

async function setConfig(key: string, value: unknown) {
  await getSequelize().query(
    `INSERT INTO system_config (key, value, "createdAt", "updatedAt")
     VALUES (:key, CAST(:value AS jsonb), now(), now())
     ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
    { replacements: { key, value: JSON.stringify(value) } },
  );
}

function nativeClient(overrides: Partial<OidcClientAttributes> = {}) {
  return OidcClient.create({
    id: `cli-${randomUUID()}`,
    name: 'Seamless CLI',
    firstParty: true,
    clientType: 'public',
    tokenEndpointAuthMethod: 'none',
    redirectUris: ['http://127.0.0.1/callback'],
    sessionExchangeEnabled: true,
    ...overrides,
  });
}

async function configure({
  enabled = true,
  issuer = PROVIDER_ISSUER as string | null,
  clientId,
}: {
  enabled?: boolean;
  issuer?: string | null;
  clientId: string | null;
}) {
  await SystemConfig.destroy({ where: { key: KEYS } });
  await setConfig('oidc_provider_enabled', enabled);
  if (issuer) await setConfig('oidc_issuer', issuer);
  if (clientId) await setConfig('oidc_cli_client_id', clientId);
  invalidateSystemConfigCache();
}

async function admin(roles = ['admin:write', 'admin:read'], stepUp = true) {
  const user = await User.create({
    email: `${randomUUID()}@public-oidc-provider.test`,
    phone: null,
    roles,
  } as never);
  const now = Date.now();
  const session = await Session.create({
    userId: user.id,
    mode: 'server',
    refreshTokenLookup: randomUUID().replaceAll('-', ''),
    expiresAt: new Date(now + 3_600_000),
    idleExpiresAt: new Date(now + 3_600_000),
    lastUsedAt: new Date(now),
    chainStartedAt: new Date(now),
    ...(stepUp ? { stepUpVerifiedAt: new Date(now) } : {}),
  });
  return { token: await tokens.signAccessToken(session.id, session.userId, roles, null) };
}

function patchConfig(token: string, body: Record<string, unknown>) {
  return request(app)
    .patch('/system-config/admin')
    .set('Authorization', `Bearer ${token}`)
    .send(body);
}

function readPublic() {
  return request(app).get('/system-config/public');
}

beforeAll(async () => {
  setEnv({
    ISSUER: API_ISSUER,
    ALLOW_UNCREDENTIALED_DELIVERY_SECRETS: 'true',
    DISABLE_AUTH_RATE_LIMITS: 'true',
    SEAMLESS_DEV_KEYS_DIR: fs.mkdtempSync(path.join(os.tmpdir(), 'seamless-keys-')),
    OIDC_JWKS_ACTIVE_KID: 'public-provider-key',
    OIDC_JWKS_KEYS: JSON.stringify({
      keys: [{ ...providerKey.export({ format: 'jwk' }), kid: 'public-provider-key' }],
    }),
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

  tokens = await import('../../src/lib/token.js');
  const { initDevSigningKey } = await import('../../src/utils/signingKeyStore.js');
  const { createApp } = await import('../../src/app.js');
  initDevSigningKey();
  app = await createApp();
});

afterAll(async () => {
  await SystemConfig.destroy({ where: { key: KEYS } });
  await getSequelize().query(`DELETE FROM users WHERE email LIKE :pattern`, {
    replacements: { pattern: '%@public-oidc-provider.test' },
  });
  invalidateSystemConfigCache();
  for (const [key, value] of Object.entries(savedEnv)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  await getSequelize().close();
});

beforeEach(async () => {
  await SystemConfig.destroy({ where: { key: KEYS } });
  invalidateSystemConfigCache();
});

describe('GET /system-config/public oidcProvider', () => {
  it('advertises the issuer and client when every condition holds', async () => {
    const client = await nativeClient();
    await configure({ clientId: client.id });

    const res = await readPublic();

    expect(res.status).toBe(200);
    expect(res.body.oidcProvider).toEqual({ issuer: PROVIDER_ISSUER, cliClientId: client.id });
    expect(Object.keys(res.body.oidcProvider)).toEqual(['issuer', 'cliClientId']);
  });

  it('is never stored by a cache between the caller and the API', async () => {
    const client = await nativeClient();
    await configure({ clientId: client.id });

    expect((await readPublic()).headers['cache-control']).toBe('no-store');
  });

  async function expectAbsent() {
    const res = await readPublic();

    expect(res.status).toBe(200);
    expect(Object.keys(res.body)).toEqual(WITHOUT_ADVERTISEMENT);
  }

  it('is absent on an instance with none of the keys', async () => {
    await expectAbsent();
  });

  it('is absent while the provider is off', async () => {
    const client = await nativeClient();
    await configure({ enabled: false, clientId: client.id });

    await expectAbsent();
  });

  it('is absent with no issuer, rather than sending the client alone', async () => {
    const client = await nativeClient();
    await configure({ issuer: null, clientId: client.id });

    await expectAbsent();
  });

  it('is absent with no client, rather than sending the issuer alone', async () => {
    await configure({ clientId: null });

    await expectAbsent();
  });

  it('is absent when the application does not exist', async () => {
    await configure({ clientId: `missing-${randomUUID()}` });

    await expectAbsent();
  });

  it('is absent when the application is disabled', async () => {
    const client = await nativeClient({ disabledAt: new Date() });
    await configure({ clientId: client.id });

    await expectAbsent();
  });

  it.each<[string, Partial<OidcClientAttributes>]>([
    ['has exchange off', { sessionExchangeEnabled: false }],
    ['is third-party', { firstParty: false }],
    ['is confidential', CONFIDENTIAL],
    ['has no native redirect', { redirectUris: ['https://app.example.com/callback'] }],
  ])('is absent when the application %s', async (_name, overrides) => {
    const client = await nativeClient(overrides);
    await configure({ clientId: client.id });

    await expectAbsent();
  });
});

describe('the application changing after it was named', () => {
  it('disappears when the application is disabled, and returns when re-enabled', async () => {
    const client = await nativeClient();
    await configure({ clientId: client.id });
    const { token } = await admin();
    const update = (body: Record<string, unknown>) =>
      request(app)
        .patch(`/admin/applications/${client.id}`)
        .set('Authorization', `Bearer ${token}`)
        .send(body);

    expect((await readPublic()).body.oidcProvider).toBeDefined();

    expect((await update({ disabled: true })).status).toBe(200);
    expect((await readPublic()).body).not.toHaveProperty('oidcProvider');

    expect((await update({ disabled: false })).status).toBe(200);
    expect((await readPublic()).body.oidcProvider?.cliClientId).toBe(client.id);
  });

  it('disappears when its exchange is turned off', async () => {
    const client = await nativeClient();
    await configure({ clientId: client.id });
    const { token } = await admin();

    const res = await request(app)
      .patch(`/admin/applications/${client.id}`)
      .set('Authorization', `Bearer ${token}`)
      .send({ sessionExchangeEnabled: false });

    expect(res.status).toBe(200);
    expect((await readPublic()).body).not.toHaveProperty('oidcProvider');
  });

  it('disappears when the application is deleted', async () => {
    const client = await nativeClient();
    await configure({ clientId: client.id });
    const { token } = await admin();

    const res = await request(app)
      .delete(`/admin/applications/${client.id}`)
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect((await readPublic()).body).not.toHaveProperty('oidcProvider');
  });

  it('leaves the stored key in place, so other config can still be patched', async () => {
    const client = await nativeClient();
    await configure({ clientId: client.id });
    await client.update({ disabledAt: new Date() });
    const { token } = await admin();

    const res = await patchConfig(token, { app_name: 'Still Patchable' });

    expect(res.status).toBe(200);
    expect((await SystemConfig.findByPk('oidc_cli_client_id'))?.value).toBe(client.id);
  });
});

describe('PATCH /system-config/admin oidc_cli_client_id', () => {
  it('stores an eligible application, audits it, and advertises it at once', async () => {
    const client = await nativeClient();
    await configure({ clientId: null });
    await readPublic();
    const { token } = await admin();

    const res = await patchConfig(token, { oidc_cli_client_id: client.id });

    expect(res.status).toBe(200);
    expect(res.body.updatedKeys).toEqual(['oidc_cli_client_id']);
    expect((await SystemConfig.findByPk('oidc_cli_client_id'))?.value).toBe(client.id);
    expect((await readPublic()).body.oidcProvider).toEqual({
      issuer: PROVIDER_ISSUER,
      cliClientId: client.id,
    });

    const events = await AuthEvent.findAll({ where: { type: 'system_config_updated' } });
    expect(events.some((event) => event.metadata?.after?.oidc_cli_client_id === client.id)).toBe(
      true,
    );
  });

  it('is readable back through the admin route', async () => {
    const client = await nativeClient();
    await configure({ clientId: client.id });
    const { token } = await admin(['admin:read']);

    const res = await request(app)
      .get('/system-config/admin')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body.oidc_cli_client_id).toBe(client.id);
  });

  it('needs a fresh step-up', async () => {
    const client = await nativeClient();
    const { token } = await admin(['admin:write', 'admin:read'], false);

    const res = await patchConfig(token, { oidc_cli_client_id: client.id });

    expect(res.status).toBe(403);
    expect(res.body.error).toBe('step_up_required');
    expect(await SystemConfig.findByPk('oidc_cli_client_id')).toBeNull();
  });

  it('refuses an unknown application', async () => {
    const { token } = await admin();

    const res = await patchConfig(token, { oidc_cli_client_id: `missing-${randomUUID()}` });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('Invalid OpenID Provider config');
    expect(await SystemConfig.findByPk('oidc_cli_client_id')).toBeNull();
  });

  it.each<[string, Partial<OidcClientAttributes>]>([
    ['is disabled', { disabledAt: new Date() }],
    ['has exchange off', { sessionExchangeEnabled: false }],
    ['is third-party', { firstParty: false }],
    ['is confidential', CONFIDENTIAL],
    ['has no native redirect', { redirectUris: ['https://app.example.com/callback'] }],
  ])('refuses an application that %s', async (_name, overrides) => {
    const client = await nativeClient(overrides);
    const { token } = await admin();

    const res = await patchConfig(token, { oidc_cli_client_id: client.id });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('Invalid OpenID Provider config');
    expect(await SystemConfig.findByPk('oidc_cli_client_id')).toBeNull();
  });

  it('refuses an empty id', async () => {
    const { token } = await admin();

    expect((await patchConfig(token, { oidc_cli_client_id: '' })).status).toBe(400);
  });

  it('clears the key with null, on the NOT NULL value column', async () => {
    const client = await nativeClient();
    await configure({ clientId: client.id });
    const { token } = await admin();

    const res = await patchConfig(token, { oidc_cli_client_id: null });

    expect(res.status).toBe(200);
    expect(await SystemConfig.findByPk('oidc_cli_client_id')).toBeNull();
    expect((await readPublic()).body).not.toHaveProperty('oidcProvider');

    const read = await request(app)
      .get('/system-config/admin')
      .set('Authorization', `Bearer ${token}`);
    expect(read.status).toBe(200);
    expect(read.body.oidc_cli_client_id).toBeNull();
  });

  it('clears a key naming an application that no longer exists', async () => {
    await configure({ clientId: `gone-${randomUUID()}` });
    const { token } = await admin();

    expect((await patchConfig(token, { oidc_cli_client_id: null })).status).toBe(200);
    expect(await SystemConfig.findByPk('oidc_cli_client_id')).toBeNull();
  });
});
