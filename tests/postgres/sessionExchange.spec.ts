import { generateKeyPairSync, randomUUID } from 'crypto';
import fs from 'fs';
import { SignJWT } from 'jose';
import os from 'os';
import path from 'path';
import request from 'supertest';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { invalidateSystemConfigCache } from '../../src/config/getSystemConfig.js';
import { AuthEvent } from '../../src/models/authEvents.js';
import { getSequelize, initializeModels } from '../../src/models/index.js';
import { OidcClient, type OidcClientAttributes } from '../../src/models/oidcClients.js';
import { OidcPayload } from '../../src/models/oidcPayloads.js';
import { Session, type SessionAttributes } from '../../src/models/sessions.js';
import { SystemConfig } from '../../src/models/systemConfig.js';
import { User } from '../../src/models/users.js';
import { buildSystemConfig } from '../factories/systemConfigFactory.js';

const API_ISSUER = 'http://localhost:5312';
const PROVIDER_ISSUER = 'https://login.session-exchange.test';
const BUILT_IN_RESOURCE = `${PROVIDER_ISSUER}/seamless`;
const KID = 'exchange-key';
const AUTHORIZATION_CODE = 'authorization_code';
const DEVICE_CODE = 'urn:ietf:params:oauth:grant-type:device_code';
const SCOPE = 'session:exchange';

const providerKey = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey;

type App = Awaited<ReturnType<typeof import('../../src/app.js').createApp>>;
type Signing = typeof import('../../src/services/oidcSigning.js');
type Registry = typeof import('../../src/services/oidcClientRegistry.js');
type Applications = typeof import('../../src/services/oidcApplicationService.js');
type Store = typeof import('../../src/services/oidcPayloadStore.js');
type Tokens = typeof import('../../src/lib/token.js');

let app: App;
let signing: Signing;
let registry: Registry;
let applications: Applications;
let store: Store;
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

beforeAll(async () => {
  setEnv({
    ISSUER: API_ISSUER,
    ALLOW_UNCREDENTIALED_DELIVERY_SECRETS: 'true',
    DISABLE_AUTH_RATE_LIMITS: 'true',
    SEAMLESS_DEV_KEYS_DIR: fs.mkdtempSync(path.join(os.tmpdir(), 'seamless-keys-')),
    OIDC_JWKS_ACTIVE_KID: KID,
    OIDC_JWKS_KEYS: JSON.stringify({
      keys: [{ ...providerKey.export({ format: 'jwk' }), kid: KID }],
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
  await setConfig('oidc_issuer', PROVIDER_ISSUER);
  await setConfig('max_concurrent_sessions', null);
  invalidateSystemConfigCache();

  signing = await import('../../src/services/oidcSigning.js');
  registry = await import('../../src/services/oidcClientRegistry.js');
  applications = await import('../../src/services/oidcApplicationService.js');
  store = await import('../../src/services/oidcPayloadStore.js');
  tokens = await import('../../src/lib/token.js');

  const { initDevSigningKey } = await import('../../src/utils/signingKeyStore.js');
  const { createApp } = await import('../../src/app.js');
  initDevSigningKey();
  app = await createApp();
});

afterAll(async () => {
  await SystemConfig.destroy({ where: { key: ['oidc_issuer', 'max_concurrent_sessions'] } });
  await getSequelize().query(`DELETE FROM users WHERE email LIKE :pattern`, {
    replacements: { pattern: '%@session-exchange.test' },
  });
  invalidateSystemConfigCache();
  for (const [key, value] of Object.entries(savedEnv)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  await getSequelize().close();
});

beforeEach(() => {
  invalidateSystemConfigCache();
});

function nativeClient(overrides: Partial<OidcClientAttributes> = {}) {
  return OidcClient.create({
    id: `cli-${randomUUID()}`,
    name: 'Seamless CLI',
    firstParty: true,
    clientType: 'public',
    tokenEndpointAuthMethod: 'none',
    redirectUris: ['http://127.0.0.1/callback'],
    grantTypes: [AUTHORIZATION_CODE, DEVICE_CODE],
    deviceFlowEnabled: true,
    sessionExchangeEnabled: true,
    ...overrides,
  });
}

function createUser(roles: string[] = ['user']) {
  return User.create({
    email: `${randomUUID()}@session-exchange.test`,
    phone: null,
    roles,
  } as never);
}

function createSession(userId: string, overrides: Partial<SessionAttributes> = {}) {
  const now = Date.now();
  return Session.create({
    userId,
    mode: 'server',
    refreshTokenLookup: randomUUID().replaceAll('-', ''),
    expiresAt: new Date(now + 3_600_000),
    idleExpiresAt: new Date(now + 3_600_000),
    lastUsedAt: new Date(now),
    chainStartedAt: new Date(now),
    ...overrides,
  });
}

/** The first-party session a provider sign-in produced for the client (ADR 0001, D3). */
async function providerSignIn(
  client: OidcClient,
  user: User,
  overrides: Partial<SessionAttributes> = {},
) {
  const parent = await createSession(user.id, overrides);
  await store.bindOidcSession(parent.id, user.id, client.id);
  await store.upsertOidcPayload('Grant', randomUUID(), {
    payload: { accountId: user.id, clientId: client.id },
    expiresIn: 3600,
    sessionId: parent.id,
  });
  return parent;
}

function accessTokenFor(session: Session, roles: string[] = ['user']) {
  return tokens.signAccessToken(session.id, session.userId, roles, null);
}

function jwtInput(header: Record<string, unknown>, claims: Record<string, unknown>) {
  const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${encode(header)}.${encode(claims)}`;
}

function subjectClaims(client: OidcClient, userId: string, overrides = {}) {
  const now = Math.floor(Date.now() / 1000);
  return {
    iss: PROVIDER_ISSUER,
    sub: userId,
    aud: BUILT_IN_RESOURCE,
    exp: now + 60,
    iat: now,
    jti: randomUUID(),
    client_id: client.id,
    scope: SCOPE,
    ...overrides,
  };
}

/** Has `/oidc/sign` sign an access token, the way the edge asks for one. */
async function signSubject(
  client: OidcClient,
  parent: Session,
  { grantType = AUTHORIZATION_CODE, claims = {} } = {},
) {
  const body = subjectClaims(client, parent.userId, claims);
  const signingInput = jwtInput({ alg: 'RS256', kid: KID, typ: 'at+jwt' }, body);
  const outcome = await signing.signForOidcEdge({
    kind: 'access_token',
    kid: KID,
    clientId: client.id,
    sessionId: parent.id,
    grantType,
    signingInput,
  } as never);
  return {
    outcome,
    jti: body.jti as string,
    token: outcome.ok ? `${signingInput}.${outcome.signature}` : '',
  };
}

async function admin(roles = ['admin:write', 'admin:read'], stepUp = true) {
  const user = await createUser(roles);
  const session = await createSession(user.id, stepUp ? { stepUpVerifiedAt: new Date() } : {});
  return { user, session, token: await accessTokenFor(session, roles) };
}

describe('the sessionExchangeEnabled registry flag', () => {
  it('adds the built-in resource for an eligible client, with a 60 second lifetime', async () => {
    const client = await nativeClient();

    expect(await registry.getOidcClientResources(client.id)).toEqual([
      { identifier: BUILT_IN_RESOURCE, scopes: [SCOPE], accessTokenTtlSeconds: 60 },
    ]);
  });

  it('keeps one built-in entry when notices are on as well', async () => {
    const client = await nativeClient({ noticesEnabled: true });
    const resources = await registry.getOidcClientResources(client.id);

    expect(resources).toHaveLength(1);
    expect(resources[0].scopes.sort()).toEqual(['notices:send', SCOPE]);
    expect(resources[0].accessTokenTtlSeconds).toBe(60);
  });

  it.each([
    ['the flag is off', { sessionExchangeEnabled: false }],
    ['the client is third-party', { firstParty: false }],
    [
      'the client is confidential',
      { clientType: 'confidential', tokenEndpointAuthMethod: 'private_key_jwt' },
    ],
    ['the client is a web client', { redirectUris: ['https://app.example.com/callback'] }],
    ['the client is disabled', { disabledAt: new Date() }],
  ] as [string, Partial<OidcClientAttributes>][])(
    'lists nothing when %s, whatever is stored',
    async (_name, overrides) => {
      const client = await nativeClient(overrides);

      expect(await registry.getOidcClientResources(client.id)).toEqual([]);
    },
  );

  it('is off by default and refused on a client that is not first-party public native', async () => {
    const { client } = await applications.createOidcApplication({
      name: 'Default',
      clientType: 'public',
      firstParty: true,
      redirectUris: ['http://127.0.0.1/callback'],
      grantTypes: ['authorization_code'],
    } as never);
    expect(client.sessionExchangeEnabled).toBe(false);

    const web = await nativeClient({
      sessionExchangeEnabled: false,
      redirectUris: ['https://app.example.com/callback'],
    });
    await expect(
      applications.updateOidcApplication(web.id, { sessionExchangeEnabled: true }),
    ).rejects.toBeInstanceOf(applications.OidcApplicationInvalidError);
    await web.reload();
    expect(web.sessionExchangeEnabled).toBe(false);
  });

  it('refuses an update that would make an enabled client ineligible', async () => {
    const client = await nativeClient();

    await expect(
      applications.updateOidcApplication(client.id, {
        redirectUris: ['https://app.example.com/callback'],
      }),
    ).rejects.toBeInstanceOf(applications.OidcApplicationInvalidError);
    await expect(
      applications.updateOidcApplication(client.id, { firstParty: false }),
    ).rejects.toBeInstanceOf(applications.OidcApplicationError);
  });

  async function exchangedSessions(client: OidcClient) {
    const user = await createUser();
    const parent = await createSession(user.id);
    const child = await createSession(user.id, {
      parentSessionId: parent.id,
      exchangeClientId: client.id,
      exchangeGrantType: AUTHORIZATION_CODE,
    });
    const rotated = await createSession(user.id, {
      parentSessionId: parent.id,
      exchangeClientId: client.id,
      exchangeGrantType: AUTHORIZATION_CODE,
    });
    return { parent, child, rotated };
  }

  it('revokes what the client exchanged for when the flag goes off, and only that', async () => {
    const client = await nativeClient();
    const other = await nativeClient();
    const { parent, child, rotated } = await exchangedSessions(client);
    const unrelated = await exchangedSessions(other);

    await applications.updateOidcApplication(client.id, { sessionExchangeEnabled: false });

    await child.reload();
    await rotated.reload();
    await parent.reload();
    await unrelated.child.reload();
    expect(child.revokedReason).toBe('session_exchange_disabled');
    expect(rotated.revokedAt).not.toBeNull();
    expect(parent.revokedAt).toBeNull();
    expect(unrelated.child.revokedAt).toBeNull();
    expect(await registry.getOidcClientResources(client.id)).toEqual([]);
  });

  it('revokes what the client exchanged for when the client is disabled', async () => {
    const client = await nativeClient();
    const { child } = await exchangedSessions(client);

    await applications.updateOidcApplication(client.id, { disabled: true });

    await child.reload();
    expect(child.revokedReason).toBe('oidc_client_disabled');
  });

  it('revokes what the client exchanged for when the client is deleted', async () => {
    const client = await nativeClient();
    const { child } = await exchangedSessions(client);

    await applications.deleteOidcApplication(client.id);

    await child.reload();
    expect(child.revokedReason).toBe('oidc_client_deleted');
  });

  it('leaves exchanged sessions alone on an unrelated update', async () => {
    const client = await nativeClient();
    const { child } = await exchangedSessions(client);

    await applications.updateOidcApplication(client.id, { name: 'Renamed' });

    await child.reload();
    expect(child.revokedAt).toBeNull();
  });

  describe('on the admin routes', () => {
    it('needs a step-up, and audits the change', async () => {
      const client = await nativeClient({ sessionExchangeEnabled: false });
      const noStepUp = await admin(['admin:write'], false);

      const refused = await request(app)
        .patch(`/admin/applications/${client.id}`)
        .set('Authorization', `Bearer ${noStepUp.token}`)
        .send({ sessionExchangeEnabled: true });
      expect(refused.status).toBe(403);
      expect(refused.body.error).toBe('step_up_required');

      const stepped = await admin();
      const res = await request(app)
        .patch(`/admin/applications/${client.id}`)
        .set('Authorization', `Bearer ${stepped.token}`)
        .send({ sessionExchangeEnabled: true });

      expect(res.status).toBe(200);
      expect(res.body.application.sessionExchangeEnabled).toBe(true);
      const events = await AuthEvent.findAll({
        where: { type: 'admin_oidc_application_session_exchange_updated' },
      });
      expect(
        events.some(
          (event) =>
            (event.metadata as Record<string, unknown>)?.clientId === client.id &&
            (event.metadata as Record<string, unknown>)?.sessionExchangeEnabled === true,
        ),
      ).toBe(true);
    });

    it('answers 400 for a client that is not eligible', async () => {
      const web = await nativeClient({
        sessionExchangeEnabled: false,
        redirectUris: ['https://app.example.com/callback'],
      });
      const { token } = await admin();

      const res = await request(app)
        .patch(`/admin/applications/${web.id}`)
        .set('Authorization', `Bearer ${token}`)
        .send({ sessionExchangeEnabled: true });

      expect(res.status).toBe(400);
    });

    it('audits an application created with the flag on', async () => {
      const { token } = await admin();

      const res = await request(app)
        .post('/admin/applications')
        .set('Authorization', `Bearer ${token}`)
        .send({
          name: 'Created',
          clientType: 'public',
          firstParty: true,
          redirectUris: ['http://127.0.0.1/callback'],
          grantTypes: ['authorization_code'],
          sessionExchangeEnabled: true,
        });

      expect(res.status).toBe(201);
      expect(res.body.application.sessionExchangeEnabled).toBe(true);
      const events = await AuthEvent.findAll({
        where: { type: 'admin_oidc_application_session_exchange_updated' },
      });
      expect(
        events.some(
          (event) =>
            (event.metadata as Record<string, unknown>)?.clientId === res.body.application.id,
        ),
      ).toBe(true);
    });
  });
});
