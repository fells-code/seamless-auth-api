import { generateKeyPairSync, randomUUID } from 'crypto';
import fs from 'fs';
import { SignJWT } from 'jose';
import os from 'os';
import path from 'path';
import request from 'supertest';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

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
type Sessions = typeof import('../../src/services/sessionService.js');

let app: App;
let signing: Signing;
let registry: Registry;
let applications: Applications;
let store: Store;
let tokens: Tokens;
let sessions: Sessions;
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
  sessions = await import('../../src/services/sessionService.js');

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

describe('/oidc/sign for a session:exchange token', () => {
  async function eligible(overrides: Partial<SessionAttributes> = {}) {
    const client = await nativeClient();
    const user = await createUser();
    const parent = await providerSignIn(client, user, overrides);
    return { client, user, parent };
  }

  it('signs it, and records which session and grant it came from', async () => {
    const { client, user, parent } = await eligible();

    const { outcome, jti } = await signSubject(client, parent, { grantType: DEVICE_CODE });

    expect(outcome.ok).toBe(true);
    const record = await OidcPayload.findOne({ where: { model: 'SessionExchangeToken', id: jti } });
    expect(record?.sessionId).toBe(parent.id);
    expect(record?.consumedAt).toBeNull();
    expect(record?.payload).toEqual({
      clientId: client.id,
      accountId: user.id,
      grantType: DEVICE_CODE,
    });
  });

  it('expires the record with the token', async () => {
    const { client, parent } = await eligible();
    const exp = Math.floor(Date.now() / 1000) + 90;

    const { jti } = await signSubject(client, parent, { claims: { exp } });

    const record = await OidcPayload.findOne({ where: { model: 'SessionExchangeToken', id: jti } });
    expect(record?.expiresAt.getTime()).toBe(exp * 1000);
  });

  it('records nothing for a token with no session:exchange scope', async () => {
    const client = await nativeClient({ noticesEnabled: true });
    const user = await createUser();
    const parent = await providerSignIn(client, user);

    const { outcome, jti } = await signSubject(client, parent, {
      claims: { scope: 'notices:send' },
    });

    expect(outcome.ok).toBe(true);
    expect(await OidcPayload.count({ where: { model: 'SessionExchangeToken', id: jti } })).toBe(0);
  });

  it.each([
    ['another scope with it', { scope: `${SCOPE} notices:send` }, 'grant_not_allowed'],
    ['an OIDC scope with it', { scope: `openid ${SCOPE}` }, 'grant_not_allowed'],
    ['an audience list', { aud: [BUILT_IN_RESOURCE] }, 'audience_mismatch'],
    ['another audience', { aud: 'https://api.example.com' }, 'audience_mismatch'],
    ['no jti', { jti: undefined }, 'malformed_signing_input'],
    ['no iat', { iat: undefined }, 'malformed_signing_input'],
    [
      'a lifetime over two minutes',
      { exp: Math.floor(Date.now() / 1000) + 600 },
      'malformed_signing_input',
    ],
    [
      'an iat that hides a longer lifetime',
      { iat: Math.floor(Date.now() / 1000) + 1000, exp: Math.floor(Date.now() / 1000) + 1100 },
      'malformed_signing_input',
    ],
  ] as [string, Record<string, unknown>, string][])(
    'refuses a token with %s',
    async (_name, claims, code) => {
      const { client, parent } = await eligible();

      const { outcome } = await signSubject(client, parent, { claims });

      expect(outcome).toMatchObject({ ok: false, code });
    },
  );

  it('refuses another resource that happens to declare the scope', async () => {
    const { client, parent } = await eligible();
    const identifier = `https://api-${randomUUID()}.example.com`;
    const { createOidcResource, setOidcApplicationResources } =
      await import('../../src/services/oidcResourceService.js');
    const resource = await createOidcResource({
      identifier,
      name: 'Lookalike',
      scopes: [SCOPE],
    } as never);
    await setOidcApplicationResources(client.id, {
      resources: [{ resourceId: resource.id, scopes: [SCOPE] }],
    } as never);

    const { outcome } = await signSubject(client, parent, { claims: { aud: identifier } });

    expect(outcome).toMatchObject({ ok: false, code: 'audience_mismatch' });
  });

  it('refuses a refresh grant, which has no business minting one', async () => {
    const client = await nativeClient({
      grantTypes: [AUTHORIZATION_CODE, 'refresh_token', DEVICE_CODE],
    });
    const parent = await providerSignIn(client, await createUser());

    const { outcome } = await signSubject(client, parent, { grantType: 'refresh_token' });

    expect(outcome).toMatchObject({ ok: false, code: 'grant_not_allowed' });
  });

  it.each([
    ['exchange is off', { sessionExchangeEnabled: false }, 'audience_mismatch'],
    ['it is a web client', { redirectUris: ['https://app.example.com/cb'] }, 'audience_mismatch'],
    ['it is disabled', { disabledAt: new Date() }, 'client_inactive'],
  ] as [string, Partial<OidcClientAttributes>, string][])(
    'refuses a client when %s',
    async (_name, overrides, code) => {
      const client = await nativeClient(overrides);
      const parent = await providerSignIn(client, await createUser());

      const { outcome } = await signSubject(client, parent);

      expect(outcome).toMatchObject({ ok: false, code });
    },
  );

  it('never signs the scope onto a client credentials token', async () => {
    const client = await nativeClient({
      grantTypes: ['client_credentials', AUTHORIZATION_CODE],
    });
    const claims = subjectClaims(client, client.id);
    const signingInput = jwtInput({ alg: 'RS256', kid: KID, typ: 'at+jwt' }, claims);

    const outcome = await signing.signForOidcEdge({
      kind: 'client_credentials',
      kid: KID,
      clientId: client.id,
      grantType: 'client_credentials',
      signingInput,
    } as never);

    expect(outcome).toMatchObject({ ok: false, code: 'grant_not_allowed' });
  });

  it('refuses to sign the same jti twice, so a consumed record cannot be reset', async () => {
    const { client, parent } = await eligible();
    const { jti } = await signSubject(client, parent);
    await OidcPayload.update(
      { consumedAt: new Date() },
      { where: { model: 'SessionExchangeToken', id: jti } },
    );

    const { outcome } = await signSubject(client, parent, { claims: { jti } });

    expect(outcome).toMatchObject({ ok: false, code: 'malformed_signing_input' });
    const record = await OidcPayload.findOne({ where: { model: 'SessionExchangeToken', id: jti } });
    expect(record?.consumedAt).not.toBeNull();
  });

  it('keeps the record out of reach of the edge payload routes', async () => {
    const { OidcPayloadModelSchema } = await import('@seamless-auth/types');

    expect(OidcPayloadModelSchema.safeParse('SessionExchangeToken').success).toBe(false);
  });
});

const GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:token-exchange';
const ACCESS_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token';
const REFRESH_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:refresh_token';
const TOKEN_FAILURE = { error: 'invalid_request' };

function exchange(subjectToken: string, overrides: Record<string, unknown> = {}) {
  return request(app)
    .post('/sessions/exchange')
    .send({
      grant_type: GRANT_TYPE,
      subject_token: subjectToken,
      subject_token_type: ACCESS_TOKEN_TYPE,
      requested_token_type: REFRESH_TOKEN_TYPE,
      ...overrides,
    });
}

async function signedInToCli(
  overrides: Partial<SessionAttributes> = {},
  clientOverrides: Partial<OidcClientAttributes> = {},
  roles: string[] = ['user'],
) {
  const client = await nativeClient(clientOverrides);
  const user = await createUser(roles);
  const parent = await providerSignIn(client, user, overrides);
  return { client, user, parent };
}

/** A token signed with the provider key that `/oidc/sign` never saw. */
function forge(claims: Record<string, unknown>, typ = 'at+jwt') {
  return new SignJWT(claims).setProtectedHeader({ alg: 'RS256', kid: KID, typ }).sign(providerKey);
}

function me(token: string) {
  return request(app).get('/users/me').set('Authorization', `Bearer ${token}`);
}

describe('POST /sessions/exchange', () => {
  it('issues a linked child session the first-party routes accept', async () => {
    const { client, user, parent } = await signedInToCli();
    const { token, jti } = await signSubject(client, parent);

    const res = await exchange(token);

    expect(res.status).toBe(200);
    expect(res.headers['cache-control']).toBe('no-store');
    expect(res.body).toMatchObject({
      message: 'Success',
      sub: user.id,
      email: user.email,
      roles: user.roles,
      issued_token_type: REFRESH_TOKEN_TYPE,
    });
    expect(res.body.ttl).toBeGreaterThan(0);
    expect(res.body.refreshTtl).toBeGreaterThan(0);
    expect(res.body.sessionId).not.toBe(parent.id);

    const child = await Session.findByPk(res.body.sessionId);
    expect(child).toMatchObject({
      userId: user.id,
      parentSessionId: parent.id,
      exchangeClientId: client.id,
      exchangeGrantType: AUTHORIZATION_CODE,
      organizationId: parent.organizationId,
    });
    expect(child?.refreshTokenLookup).not.toBe(parent.refreshTokenLookup);

    const record = await OidcPayload.findOne({ where: { model: 'SessionExchangeToken', id: jti } });
    expect(record?.consumedAt).not.toBeNull();

    expect((await me(res.body.token)).status).toBe(200);
    expect((await me(await accessTokenFor(parent))).status).toBe(200);

    const refreshed = await request(app)
      .post('/refresh')
      .set('Authorization', `Bearer ${res.body.refreshToken}`);
    expect(refreshed.status).toBe(200);

    const event = await AuthEvent.findOne({
      where: { type: 'session_exchanged', session_id: res.body.sessionId },
    });
    expect(event?.user_id).toBe(user.id);
    expect(event?.metadata).toMatchObject({
      clientId: client.id,
      grantType: AUTHORIZATION_CODE,
      parentSessionId: parent.id,
    });
  });

  it('accepts a request that leaves out the optional requested_token_type', async () => {
    const { client, parent } = await signedInToCli();
    const { token } = await signSubject(client, parent);

    const res = await exchange(token, { requested_token_type: undefined });

    expect(res.status).toBe(200);
  });

  it('caps the child at what is left of the parent', async () => {
    const parentExpiry = new Date(Date.now() + 30 * 60_000);
    const { client, parent } = await signedInToCli({
      expiresAt: parentExpiry,
      idleExpiresAt: parentExpiry,
    });
    const { token } = await signSubject(client, parent);

    const res = await exchange(token);

    const child = await Session.findByPk(res.body.sessionId);
    expect(child?.expiresAt.getTime()).toBeLessThanOrEqual(parentExpiry.getTime());
    expect(child?.idleExpiresAt.getTime()).toBeLessThanOrEqual(parentExpiry.getTime());
    expect(res.body.refreshTtl).toBeLessThanOrEqual(30 * 60);
  });

  it('resolves the parent forward through rotation', async () => {
    const { client, user, parent } = await signedInToCli();
    const { token } = await signSubject(client, parent);
    const rotated = await createSession(user.id, { organizationId: null });
    await Session.update({ replacedBySessionId: rotated.id }, { where: { id: parent.id } });

    const res = await exchange(token);

    expect(res.status).toBe(200);
    expect((await Session.findByPk(res.body.sessionId))?.parentSessionId).toBe(rotated.id);
  });

  describe('single use', () => {
    it('refuses a second presentation and revokes what the first one created', async () => {
      const { client, user, parent } = await signedInToCli();
      const { token } = await signSubject(client, parent);

      const first = await exchange(token);
      const second = await exchange(token);

      expect(second.status).toBe(400);
      expect(second.body).toEqual({
        error: 'invalid_request',
        error_description: 'token_already_used',
      });
      expect((await me(first.body.token)).status).toBe(401);
      const child = await Session.findByPk(first.body.sessionId);
      expect(child?.revokedReason).toBe('session_exchange_replayed');
      expect((await me(await accessTokenFor(parent))).status).toBe(200);
      const event = await AuthEvent.findOne({
        where: { type: 'session_exchange_replayed', user_id: user.id },
      });
      expect(event?.metadata).toMatchObject({ clientId: client.id });
    });

    it('revokes a child that has since rotated', async () => {
      const { client, parent } = await signedInToCli();
      const { token } = await signSubject(client, parent);
      const first = await exchange(token);
      const refreshed = await request(app)
        .post('/refresh')
        .set('Authorization', `Bearer ${first.body.refreshToken}`);

      await exchange(token);

      expect((await me(refreshed.body.token)).status).toBe(401);
    });

    it('lets one of many concurrent presentations win, then revokes it', async () => {
      const { client, user, parent } = await signedInToCli();
      const { token, jti } = await signSubject(client, parent);

      const results = await Promise.all(Array.from({ length: 6 }, () => exchange(token)));

      const winners = results.filter((res) => res.status === 200);
      const losers = results.filter((res) => res.status === 400);
      expect(winners).toHaveLength(1);
      expect(losers).toHaveLength(5);
      for (const loser of losers) {
        expect(loser.body.error_description).toBe('token_already_used');
      }
      expect((await me(winners[0].body.token)).status).toBe(401);

      const children = await Session.findAll({
        where: { userId: user.id, parentSessionId: parent.id },
      });
      expect(children).toHaveLength(1);
      expect(children[0].revokedAt).not.toBeNull();
      const record = await OidcPayload.findOne({
        where: { model: 'SessionExchangeToken', id: jti },
      });
      expect(record?.payload.childSessionId).toBe(children[0].id);
    });
  });

  describe('refuses with one body', () => {
    async function expectTokenFailure(token: string) {
      const res = await exchange(token);
      expect(res.status).toBe(400);
      expect(res.body).toEqual(TOKEN_FAILURE);
    }

    function goodClaims(client: OidcClient, userId: string) {
      return subjectClaims(client, userId);
    }

    it.each([
      ['with no signing record', {}],
      ['with another audience', { aud: 'https://api.example.com' }],
      ['with an audience list', { aud: [BUILT_IN_RESOURCE, 'https://api.example.com'] }],
      ['with an extra scope', { scope: `${SCOPE} notices:send` }],
      ['with another scope', { scope: 'notices:send' }],
      ['from another issuer', { iss: 'https://elsewhere.example.com' }],
      ['with no jti', { jti: undefined }],
      ['with no client_id', { client_id: undefined }],
    ] as [string, Record<string, unknown>][])('a token %s', async (_name, overrides) => {
      const { client, parent } = await signedInToCli();

      await expectTokenFailure(await forge({ ...goodClaims(client, parent.userId), ...overrides }));
    });

    it.each([
      ['another audience', { aud: 'https://api.example.com' }],
      ['an extra scope', { scope: `${SCOPE} notices:send` }],
    ] as [string, Record<string, unknown>][])(
      'a token with %s, even when its record exists',
      async (_name, overrides) => {
        const { client, parent } = await signedInToCli();
        const { jti } = await signSubject(client, parent);

        await expectTokenFailure(
          await forge({ ...goodClaims(client, parent.userId), jti, ...overrides }),
        );
        const record = await OidcPayload.findOne({
          where: { model: 'SessionExchangeToken', id: jti },
        });
        expect(record?.consumedAt).toBeNull();
      },
    );

    it('a token whose subject is the client', async () => {
      const { client, parent } = await signedInToCli();
      const { jti } = await signSubject(client, parent);

      await expectTokenFailure(await forge({ ...goodClaims(client, client.id), jti }));
    });

    it('a token that is not an at+jwt', async () => {
      const { client, parent } = await signedInToCli();
      const { jti } = await signSubject(client, parent);

      await expectTokenFailure(await forge({ ...goodClaims(client, parent.userId), jti }, 'JWT'));
    });

    it('a token signed by someone else', async () => {
      const { client, parent } = await signedInToCli();
      const { jti } = await signSubject(client, parent);
      const stranger = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey;
      const token = await new SignJWT({ ...goodClaims(client, parent.userId), jti })
        .setProtectedHeader({ alg: 'RS256', kid: KID, typ: 'at+jwt' })
        .sign(stranger);

      await expectTokenFailure(token);
    });

    it('a first-party access token', async () => {
      const { parent } = await signedInToCli();

      await expectTokenFailure(await accessTokenFor(parent));
    });

    it('an expired token', async () => {
      const { client, parent } = await signedInToCli();
      const { jti } = await signSubject(client, parent);
      const now = Math.floor(Date.now() / 1000);

      await expectTokenFailure(
        await forge({ ...goodClaims(client, parent.userId), jti, iat: now - 90, exp: now - 30 }),
      );
    });

    it('an expired record', async () => {
      const { client, parent } = await signedInToCli();
      const { token, jti } = await signSubject(client, parent);
      await OidcPayload.update(
        { expiresAt: new Date(Date.now() - 1000) },
        { where: { model: 'SessionExchangeToken', id: jti } },
      );

      await expectTokenFailure(token);
    });

    it('a record that names another user', async () => {
      const { client, parent } = await signedInToCli();
      const { token, jti } = await signSubject(client, parent);
      await OidcPayload.update(
        { payload: { clientId: client.id, accountId: randomUUID(), grantType: DEVICE_CODE } },
        { where: { model: 'SessionExchangeToken', id: jti } },
      );

      await expectTokenFailure(token);
    });

    it('a record that names another client', async () => {
      const { client, user, parent } = await signedInToCli();
      const { token, jti } = await signSubject(client, parent);
      await OidcPayload.update(
        { payload: { clientId: 'someone-else', accountId: user.id, grantType: DEVICE_CODE } },
        { where: { model: 'SessionExchangeToken', id: jti } },
      );

      await expectTokenFailure(token);
    });

    it.each([
      ['disabled', { disabledAt: new Date() }],
      ['no longer enabled for exchange', { sessionExchangeEnabled: false }],
      ['no longer first-party', { firstParty: false }],
      [
        'no longer public',
        { clientType: 'confidential', tokenEndpointAuthMethod: 'private_key_jwt' },
      ],
      ['no longer native', { redirectUris: ['https://app.example.com/cb'] }],
    ] as [string, Partial<OidcClientAttributes>][])('a client %s', async (_name, change) => {
      const { client, parent } = await signedInToCli();
      const { token, jti } = await signSubject(client, parent);
      await OidcClient.update(change, { where: { id: client.id } });

      await expectTokenFailure(token);
      const record = await OidcPayload.findOne({
        where: { model: 'SessionExchangeToken', id: jti },
      });
      expect(record?.consumedAt).toBeNull();
    });

    it('a recovery parent', async () => {
      const { client, parent } = await signedInToCli();
      const { token } = await signSubject(client, parent);
      await Session.update({ recovery: true }, { where: { id: parent.id } });

      await expectTokenFailure(token);
    });

    it('a parent that is no longer live', async () => {
      const { client, parent } = await signedInToCli();
      const { token } = await signSubject(client, parent);
      await Session.update({ revokedAt: new Date() }, { where: { id: parent.id } });

      await expectTokenFailure(token);
    });

    it('a parent that belongs to another user', async () => {
      const { client, parent } = await signedInToCli();
      const { token, jti } = await signSubject(client, parent);
      const stranger = await createUser();
      const elsewhere = await createSession(stranger.id);
      await OidcPayload.update(
        { sessionId: elsewhere.id },
        { where: { model: 'SessionExchangeToken', id: jti } },
      );

      await expectTokenFailure(token);
    });

    it('a parent that is itself an exchanged session', async () => {
      const { client, user, parent } = await signedInToCli();
      const { token } = await signSubject(client, parent);
      const grandparent = await createSession(user.id);
      await Session.update(
        { parentSessionId: grandparent.id, exchangeClientId: client.id },
        { where: { id: parent.id } },
      );

      await expectTokenFailure(token);
    });

    it('a revoked user', async () => {
      const { client, user, parent } = await signedInToCli();
      const { token } = await signSubject(client, parent);
      await User.update({ revoked: true }, { where: { id: user.id } });

      await expectTokenFailure(token);
    });

    it('a record with a grant that cannot exchange', async () => {
      const { client, user, parent } = await signedInToCli();
      const { token, jti } = await signSubject(client, parent);
      await OidcPayload.update(
        { payload: { clientId: client.id, accountId: user.id, grantType: 'refresh_token' } },
        { where: { model: 'SessionExchangeToken', id: jti } },
      );

      await expectTokenFailure(token);
    });
  });

  it.each([
    ['another grant type', { grant_type: 'refresh_token' }],
    ['another subject token type', { subject_token_type: 'urn:ietf:params:oauth:token-type:jwt' }],
    ['another requested type', { requested_token_type: 'urn:ietf:params:oauth:token-type:jwt' }],
    ['no subject token', { subject_token: undefined }],
  ] as [string, Record<string, unknown>][])(
    'answers invalid_request to a request with %s',
    async (_name, overrides) => {
      const res = await exchange('a.b.c', overrides);

      expect(res.status).toBe(400);
      expect(res.body.error).toBe('invalid_request');
    },
  );

  it('is not a route adapters proxy', async () => {
    const manifest = await request(app).get('/.well-known/seamless-adapter.json');

    expect(JSON.stringify(manifest.body)).not.toContain('/sessions/exchange');
  });

  describe('assurance (X5)', () => {
    const passkey = {
      method: 'passkey',
      at: '2026-11-04T12:00:00.000Z',
      deviceBound: true,
      userVerified: true,
    };

    it('copies the parent auth context for an authorization code grant', async () => {
      const authTime = new Date(Date.now() - 60_000);
      const stepUpVerifiedAt = new Date(Date.now() - 30_000);
      const { client, parent } = await signedInToCli({
        authMethods: [passkey] as never,
        authTime,
        stepUpVerifiedAt,
        stepUpMethod: 'webauthn',
      });
      const { token } = await signSubject(client, parent);

      const res = await exchange(token);

      const child = await Session.findByPk(res.body.sessionId);
      expect(child?.authMethods).toEqual([passkey]);
      expect(child?.authTime?.getTime()).toBe(authTime.getTime());
      expect(child?.stepUpVerifiedAt?.getTime()).toBe(stepUpVerifiedAt.getTime());
      expect(child?.stepUpMethod).toBe('webauthn');
    });

    it('lets a stale step-up stay stale', async () => {
      const { client, parent } = await signedInToCli({
        stepUpVerifiedAt: new Date(Date.now() - 10 * 60_000),
        stepUpMethod: 'webauthn',
      });
      const { token } = await signSubject(client, parent);

      const res = await exchange(token);

      const { getSessionStepUpStatus } = await import('../../src/services/stepUpService.js');
      const status = await getSessionStepUpStatus({
        sessionId: res.body.sessionId,
        userId: parent.userId,
      });
      expect(status.fresh).toBe(false);
    });

    it('copies nothing for a device grant', async () => {
      const { client, parent } = await signedInToCli({
        authMethods: [passkey] as never,
        authTime: new Date(),
        stepUpVerifiedAt: new Date(),
        stepUpMethod: 'webauthn',
      });
      const { token } = await signSubject(client, parent, { grantType: DEVICE_CODE });

      const res = await exchange(token);

      const child = await Session.findByPk(res.body.sessionId);
      expect(child?.exchangeGrantType).toBe(DEVICE_CODE);
      expect(child?.authMethods).toEqual([]);
      expect(child?.authTime).toBeNull();
      expect(child?.stepUpVerifiedAt).toBeNull();
      expect(child?.stepUpMethod).toBeNull();
    });

    it('keeps later step-ups on either session to that session', async () => {
      const { client, parent } = await signedInToCli();
      const { token } = await signSubject(client, parent);
      const res = await exchange(token);
      const { recordStepUpVerification } = await import('../../src/services/stepUpService.js');

      await recordStepUpVerification({
        sessionId: res.body.sessionId,
        userId: parent.userId,
        method: 'totp',
      });

      await parent.reload();
      expect(parent.stepUpVerifiedAt).toBeNull();
    });
  });

  it('refuses when the client is switched off between the checks and the write', async () => {
    // Stands in for an admin's write landing mid-exchange: the exchange's re-read after its
    // commit, or the admin's revoke after the write, has to catch it either way.
    const { client, parent } = await signedInToCli();
    const { token } = await signSubject(client, parent);
    const original = OidcClient.findByPk.bind(OidcClient);
    let reads = 0;
    const spy = vi.spyOn(OidcClient, 'findByPk').mockImplementation(async (...args) => {
      reads += 1;
      if (reads === 2) {
        await OidcClient.update({ sessionExchangeEnabled: false }, { where: { id: client.id } });
      }
      return original(...args);
    });

    const res = await exchange(token);
    spy.mockRestore();

    expect(res.status).toBe(400);
    expect(res.body).toEqual(TOKEN_FAILURE);
    const children = await Session.findAll({ where: { parentSessionId: parent.id } });
    expect(children.every((child) => child.revokedAt !== null)).toBe(true);
  });
});

describe('the child session lifecycle', () => {
  /** A signed-in parent with known refresh token, and the child exchanged from it. */
  async function family(
    parentOverrides: Partial<SessionAttributes> = {},
    roles: string[] = ['user'],
    grantType = AUTHORIZATION_CODE,
  ) {
    const parentRefresh = tokens.generateRefreshToken();
    const { client, user, parent } = await signedInToCli(
      { refreshTokenLookup: tokens.createRefreshTokenLookup(parentRefresh), ...parentOverrides },
      {},
      roles,
    );
    const { token } = await signSubject(client, parent, { grantType });
    const res = await exchange(token);
    expect(res.status).toBe(200);
    return {
      client,
      user,
      parent,
      parentRefresh,
      childId: res.body.sessionId as string,
      childToken: res.body.token as string,
      childRefresh: res.body.refreshToken as string,
    };
  }

  function refresh(token: string) {
    return request(app).post('/refresh').set('Authorization', `Bearer ${token}`);
  }

  async function expectEnded(childId: string, childToken: string) {
    expect((await me(childToken)).status).toBe(401);
    const child = await Session.findByPk(childId);
    expect(child?.revokedAt).not.toBeNull();
  }

  describe('validity', () => {
    it('refuses a child whose parent ended, even if no cascade reached it', async () => {
      const { parent, childId, childToken } = await family();
      await Session.update({ revokedAt: new Date() }, { where: { id: parent.id } });

      const row = await Session.findByPk(childId);
      expect(row?.revokedAt).toBeNull();
      expect((await me(childToken)).status).toBe(401);
    });

    it('refuses a child whose parent idled out', async () => {
      const { parent, childToken } = await family();
      await Session.update(
        { idleExpiresAt: new Date(Date.now() - 1000) },
        { where: { id: parent.id } },
      );

      expect((await me(childToken)).status).toBe(401);
    });

    it('keeps a child live while its parent rotates, and ends it with the current row', async () => {
      const { parentRefresh, childToken, childId } = await family();

      const rotated = await refresh(parentRefresh);
      expect(rotated.status).toBe(200);
      expect((await me(childToken)).status).toBe(200);

      const logout = await request(app)
        .delete('/logout')
        .set('Authorization', `Bearer ${rotated.body.token}`);
      expect(logout.status).toBe(200);

      await expectEnded(childId, childToken);
    });

    it('leaves an ordinary session with no parent alone', async () => {
      const user = await createUser();
      const session = await createSession(user.id);

      expect((await me(await accessTokenFor(session))).status).toBe(200);
    });
  });

  describe('refresh', () => {
    it('carries the link forward on rotation', async () => {
      const { client, parent, childRefresh, childId } = await family();

      const res = await refresh(childRefresh);

      expect(res.status).toBe(200);
      expect(res.body.sessionId).not.toBe(childId);
      expect(await Session.findByPk(res.body.sessionId)).toMatchObject({
        parentSessionId: parent.id,
        exchangeClientId: client.id,
        exchangeGrantType: AUTHORIZATION_CODE,
      });
    });

    it('refuses and ends a child whose parent ended', async () => {
      const { user, parent, childRefresh, childId } = await family();
      await Session.update({ revokedAt: new Date() }, { where: { id: parent.id } });

      const res = await refresh(childRefresh);

      expect(res.status).toBe(401);
      expect(res.body.error).toBe('invalid_refresh_token');
      const child = await Session.findByPk(childId);
      expect(child?.revokedReason).toBe('parent_session_ended');
      expect(child?.replacedBySessionId).toBeNull();
      const event = await AuthEvent.findOne({
        where: { type: 'refresh_token_failed', user_id: user.id, session_id: childId },
      });
      expect((event?.metadata as Record<string, unknown>)?.refusal).toBe('parent_session_ended');
    });

    it('never outlives the parent', async () => {
      const parentExpiry = new Date(Date.now() + 30 * 60_000);
      const { childRefresh } = await family({
        expiresAt: parentExpiry,
        idleExpiresAt: parentExpiry,
      });

      const res = await refresh(childRefresh);

      const child = await Session.findByPk(res.body.sessionId);
      expect(child?.expiresAt.getTime()).toBeLessThanOrEqual(parentExpiry.getTime());
      expect(child?.idleExpiresAt.getTime()).toBeLessThanOrEqual(parentExpiry.getTime());
      expect(res.body.refreshTtl).toBeLessThanOrEqual(30 * 60);
    });

    it('counts as activity on the parent, up to its absolute expiry', async () => {
      const parentExpiry = new Date(Date.now() + 2 * 3_600_000);
      const { parent, childRefresh } = await family({
        expiresAt: parentExpiry,
        idleExpiresAt: new Date(Date.now() + 60_000),
        lastUsedAt: new Date(Date.now() - 3_600_000),
      });

      const res = await refresh(childRefresh);
      expect(res.status).toBe(200);

      await parent.reload();
      expect(parent.idleExpiresAt.getTime()).toBeGreaterThan(Date.now() + 60_000);
      expect(parent.idleExpiresAt.getTime()).toBeLessThanOrEqual(parentExpiry.getTime());
      expect(parent.lastUsedAt.getTime()).toBeGreaterThan(Date.now() - 60_000);
    });

    it('revokes only the child chain on refresh token reuse', async () => {
      const { parent, childRefresh } = await family();

      const rotated = await refresh(childRefresh);
      const reused = await refresh(childRefresh);

      expect(reused.status).toBe(401);
      expect((await me(rotated.body.token)).status).toBe(401);
      await parent.reload();
      expect(parent.revokedAt).toBeNull();
      expect((await me(await accessTokenFor(parent))).status).toBe(200);
    });
  });

  describe('every way a parent ends takes the child with it', () => {
    it('logout', async () => {
      const { parent, childId, childToken } = await family();

      await request(app)
        .delete('/logout')
        .set('Authorization', `Bearer ${await accessTokenFor(parent)}`);

      await expectEnded(childId, childToken);
    });

    it('sign out everywhere', async () => {
      const { parent, childId, childToken } = await family();

      await request(app)
        .delete('/logout/all')
        .set('Authorization', `Bearer ${await accessTokenFor(parent)}`);

      await expectEnded(childId, childToken);
    });

    it('revoking the session from the user session list', async () => {
      const { parent, childId, childToken } = await family();
      const other = await createSession(parent.userId);

      const res = await request(app)
        .delete(`/sessions/${parent.id}`)
        .set('Authorization', `Bearer ${await accessTokenFor(other)}`);
      expect(res.status).toBe(200);

      await expectEnded(childId, childToken);
    });

    it('revoking all sessions from the user session list', async () => {
      const { parent, childId, childToken } = await family();

      await request(app)
        .delete('/sessions')
        .set('Authorization', `Bearer ${await accessTokenFor(parent)}`);

      await expectEnded(childId, childToken);
    });

    it('an admin revoking the session', async () => {
      const { parent, childId, childToken } = await family();
      const { token } = await admin();

      const res = await request(app)
        .delete(`/admin/sessions/by-id/${parent.id}`)
        .set('Authorization', `Bearer ${token}`);
      expect(res.status).toBe(200);

      await expectEnded(childId, childToken);
    });

    it('an admin revoking every session of the user', async () => {
      const { user, childId, childToken } = await family();
      const { token } = await admin();

      const res = await request(app)
        .delete(`/admin/sessions/${user.id}/revoke-all`)
        .set('Authorization', `Bearer ${token}`);
      expect(res.status).toBe(200);

      await expectEnded(childId, childToken);
    });

    it('refresh token reuse on the parent chain', async () => {
      const { parentRefresh, childId, childToken } = await family();

      await refresh(parentRefresh);
      const reused = await refresh(parentRefresh);
      expect(reused.status).toBe(401);

      await expectEnded(childId, childToken);
    });

    it('the provider revoking the sign-in, from the row it recorded', async () => {
      const { parent, parentRefresh, childId, childToken } = await family();
      const rotated = await refresh(parentRefresh);
      expect(rotated.status).toBe(200);

      await sessions.revokeSessionChain(parent, 'oidc_end_session');

      await expectEnded(childId, childToken);
    });

    it('concurrent session eviction', async () => {
      const { user, parent, childId, childToken } = await family();
      const { enforceConcurrentSessionLimit } =
        await import('../../src/services/concurrentSessionPolicy.js');

      const evicted = await enforceConcurrentSessionLimit({
        userId: user.id,
        limit: 1,
        req: { ip: '127.0.0.1', get: () => undefined, headers: {} } as never,
      });

      expect(evicted).toBe(1);
      await parent.reload();
      expect(parent.revokedReason).toBe('concurrent_session_limit');
      await expectEnded(childId, childToken);
    });
  });

  describe('ending a child leaves the parent alone', () => {
    it('logout', async () => {
      const { parent, childId, childToken } = await family();

      const res = await request(app).delete('/logout').set('Authorization', `Bearer ${childToken}`);
      expect(res.status).toBe(200);

      await expectEnded(childId, childToken);
      expect((await me(await accessTokenFor(parent))).status).toBe(200);
    });

    it('an admin revoking the child', async () => {
      const { parent, childId, childToken } = await family();
      const { token } = await admin();

      await request(app)
        .delete(`/admin/sessions/by-id/${childId}`)
        .set('Authorization', `Bearer ${token}`);

      await expectEnded(childId, childToken);
      expect((await me(await accessTokenFor(parent))).status).toBe(200);
    });
  });

  it('does not count a child against the concurrent session limit', async () => {
    const { user, parent, childId } = await family();
    const { enforceConcurrentSessionLimit } =
      await import('../../src/services/concurrentSessionPolicy.js');

    const evicted = await enforceConcurrentSessionLimit({
      userId: user.id,
      limit: 2,
      req: { ip: '127.0.0.1', get: () => undefined, headers: {} } as never,
    });

    expect(evicted).toBe(0);
    await parent.reload();
    expect(parent.revokedAt).toBeNull();
    expect((await Session.findByPk(childId))?.revokedAt).toBeNull();
  });
});

describe('a device child on the admin routes (X7)', () => {
  const ADMIN_ROLES = ['admin:read', 'admin:write'];

  async function child(grantType: string, roles = ADMIN_ROLES) {
    const { client, user, parent } = await signedInToCli(
      { stepUpVerifiedAt: new Date(), stepUpMethod: 'webauthn' },
      {},
      roles,
    );
    const { token } = await signSubject(client, parent, { grantType });
    const res = await exchange(token);
    return { user, parent, token: res.body.token as string, sessionId: res.body.sessionId };
  }

  function adminRead(token: string) {
    return request(app).get('/admin/users').set('Authorization', `Bearer ${token}`);
  }

  it('is refused on an admin read until it steps up, with the step-up body', async () => {
    const { token } = await child(DEVICE_CODE);

    const res = await adminRead(token);

    expect(res.status).toBe(403);
    expect(res.body).toMatchObject({ error: 'step_up_required', fresh: false, method: null });
  });

  it('borrows nothing from the approving browser', async () => {
    const { parent, token, sessionId } = await child(DEVICE_CODE);

    await parent.reload();
    expect(parent.stepUpVerifiedAt).not.toBeNull();
    expect((await adminRead(token)).status).toBe(403);
    expect((await Session.findByPk(sessionId))?.stepUpVerifiedAt).toBeNull();
  });

  it('gets in after a TOTP step-up on its own session', async () => {
    const { user, token, sessionId } = await child(DEVICE_CODE);
    const { recordStepUpVerification } = await import('../../src/services/stepUpService.js');

    await recordStepUpVerification({ sessionId, userId: user.id, method: 'totp' });

    expect((await adminRead(token)).status).toBe(200);
  });

  it('is refused again once the step-up goes stale', async () => {
    const { token, sessionId } = await child(DEVICE_CODE);
    await Session.update(
      { stepUpVerifiedAt: new Date(Date.now() - 6 * 60_000), stepUpMethod: 'totp' },
      { where: { id: sessionId } },
    );

    expect((await adminRead(token)).status).toBe(403);
  });

  it('still needs the role, and says so before it asks for a step-up', async () => {
    const { token } = await child(DEVICE_CODE, ['user']);

    const res = await adminRead(token);

    expect(res.status).toBe(403);
    expect(res.body.error).toBe('Forbidden');
  });

  it('can reach its own account without a step-up', async () => {
    const { token } = await child(DEVICE_CODE);

    expect((await me(token)).status).toBe(200);
  });

  it('does not apply to a loopback child, which inherited its step-up', async () => {
    const { token } = await child(AUTHORIZATION_CODE);

    expect((await adminRead(token)).status).toBe(200);
  });

  it('does not change a loopback child that has no step-up on an admin read', async () => {
    const { client, parent } = await signedInToCli({}, {}, ADMIN_ROLES);
    const { token: subject } = await signSubject(client, parent);
    const res = await exchange(subject);

    expect((await adminRead(res.body.token)).status).toBe(200);
  });

  it('applies to a rotated device child too', async () => {
    const { client, parent } = await signedInToCli({}, {}, ADMIN_ROLES);
    const { token: subject } = await signSubject(client, parent, { grantType: DEVICE_CODE });
    const first = await exchange(subject);
    const rotated = await request(app)
      .post('/refresh')
      .set('Authorization', `Bearer ${first.body.refreshToken}`);

    expect((await adminRead(rotated.body.token)).status).toBe(403);
  });
});

describe('session lists', () => {
  async function family(grantType = DEVICE_CODE) {
    const { client, user, parent } = await signedInToCli();
    const { token } = await signSubject(client, parent, { grantType });
    const res = await exchange(token);
    return { client, user, parent, child: res.body as Record<string, string> };
  }

  it('labels a child with its client and grant in /sessions, and leaves the parent plain', async () => {
    const { client, parent, child } = await family();

    const res = await request(app).get('/sessions').set('Authorization', `Bearer ${child.token}`);

    expect(res.status).toBe(200);
    const listed = res.body.sessions.find((row: { id: string }) => row.id === child.sessionId);
    expect(listed).toMatchObject({
      current: true,
      parentSessionId: parent.id,
      exchangeClientId: client.id,
      exchangeGrantType: DEVICE_CODE,
    });
    const plain = res.body.sessions.find((row: { id: string }) => row.id === parent.id);
    expect(plain).not.toHaveProperty('exchangeClientId');
    expect(plain).not.toHaveProperty('parentSessionId');
  });

  it.each([
    ['the user sessions view', (userId: string) => `/admin/sessions/${userId}`],
    ['the user detail view', (userId: string) => `/admin/users/${userId}`],
  ])('labels a child in %s', async (_name, url) => {
    const { client, user, child } = await family();
    const { token } = await admin();

    const res = await request(app).get(url(user.id)).set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    const listed = res.body.sessions.find((row: { id: string }) => row.id === child.sessionId);
    expect(listed).toMatchObject({
      exchangeClientId: client.id,
      exchangeGrantType: DEVICE_CODE,
    });
  });

  it('labels a child in the instance-wide view', async () => {
    const { client, child } = await family();
    const { token } = await admin();

    // Newest rows come last, and the route takes at most a page at a time.
    const first = await request(app)
      .get('/admin/sessions?limit=1')
      .set('Authorization', `Bearer ${token}`);
    const offset = Math.max(first.body.total - 50, 0);
    const res = await request(app)
      .get(`/admin/sessions?limit=50&offset=${offset}`)
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    const listed = res.body.sessions.find((row: { id: string }) => row.id === child.sessionId);
    expect(listed?.exchangeClientId).toBe(client.id);
  });
});

describe('factor changes on a device child', () => {
  const ADMIN_ROLES = ['admin:read', 'admin:write'];

  async function childOf(grantType: string, roles = ADMIN_ROLES) {
    const { client, user, parent } = await signedInToCli(
      { stepUpVerifiedAt: new Date(), stepUpMethod: 'webauthn' },
      {},
      roles,
    );
    const { token } = await signSubject(client, parent, { grantType });
    const res = await exchange(token);
    expect(res.status).toBe(200);
    return {
      user,
      parent,
      token: res.body.token as string,
      sessionId: res.body.sessionId as string,
    };
  }

  const bearer = (token: string) => ({ Authorization: `Bearer ${token}` });

  function adminRead(token: string) {
    return request(app).get('/admin/users').set(bearer(token));
  }

  /** The user's own authenticator, from before the device sign-in. */
  async function enrollTotp(user: User) {
    const { startTotpEnrollment, verifyTotpEnrollment } =
      await import('../../src/services/totpService.js');
    const { generateTotpCode, getTotpCounter } = await import('../../src/utils/totp.js');
    const { secret } = await startTotpEnrollment({
      userId: user.id,
      email: user.email,
      issuer: 'Test',
    });
    // The previous step's code, so the user's next one is not refused as a repeat.
    const enrolled = await verifyTotpEnrollment(
      user.id,
      generateTotpCode({ secret, counter: getTotpCounter() - 1 }),
    );
    expect(enrolled.verified).toBe(true);
    return { secret, code: () => generateTotpCode({ secret }) };
  }

  async function credentialsOf(userId: string) {
    const { TotpCredential } = await import('../../src/models/totpCredentials.js');
    return TotpCredential.findAll({ where: { userId } });
  }

  function expectStepUpRequired(res: request.Response) {
    expect(res.status).toBe(403);
    expect(res.body).toMatchObject({
      error: 'step_up_required',
      message: 'Recent step-up authentication is required',
      fresh: false,
      method: null,
      maxAgeSeconds: 300,
    });
  }

  it('leaves a device child with no TOTP unable to enroll one, so X7 holds', async () => {
    const { user, token } = await childOf(DEVICE_CODE);
    const { generateTotpCode, generateTotpSecret } = await import('../../src/utils/totp.js');
    const chosen = generateTotpSecret();

    expectStepUpRequired(await adminRead(token));

    expectStepUpRequired(await request(app).post('/totp/enroll/start').set(bearer(token)));
    expect(await credentialsOf(user.id)).toEqual([]);

    const code = generateTotpCode({ secret: chosen });
    expectStepUpRequired(
      await request(app).post('/totp/enroll/verify').set(bearer(token)).send({ code }),
    );

    const stepUp = await request(app).post('/totp/verify-mfa').set(bearer(token)).send({ code });
    expect(stepUp.status).toBe(401);

    expect(await credentialsOf(user.id)).toEqual([]);
    expectStepUpRequired(await adminRead(token));
  });

  it('cannot replace the TOTP of a user who has one', async () => {
    const { user, token } = await childOf(DEVICE_CODE);
    await enrollTotp(user);
    const [original] = await credentialsOf(user.id);
    const { generateTotpCode, generateTotpSecret } = await import('../../src/utils/totp.js');
    const code = generateTotpCode({ secret: generateTotpSecret() });

    expectStepUpRequired(await request(app).post('/totp/enroll/start').set(bearer(token)));
    expectStepUpRequired(
      await request(app).post('/totp/enroll/verify').set(bearer(token)).send({ code }),
    );
    expectStepUpRequired(
      await request(app).post('/totp/disable').set(bearer(token)).send({ code }),
    );

    const after = await credentialsOf(user.id);
    expect(after).toHaveLength(1);
    expect(after[0].id).toBe(original.id);
    expect(after[0].enabled).toBe(true);
    expectStepUpRequired(await adminRead(token));
  });

  it('lets a device child through once it steps up with the real TOTP', async () => {
    const { user, token } = await childOf(DEVICE_CODE);
    const { code } = await enrollTotp(user);

    expectStepUpRequired(await request(app).post('/recovery-codes').set(bearer(token)).send({}));

    const stepUp = await request(app)
      .post('/totp/verify-mfa')
      .set(bearer(token))
      .send({ code: code() });
    expect(stepUp.status).toBe(200);
    expect(stepUp.body.method).toBe('totp');

    expect((await adminRead(token)).status).toBe(200);
    expect((await request(app).post('/recovery-codes').set(bearer(token)).send({})).status).toBe(
      201,
    );
    expect((await request(app).post('/totp/enroll/start').set(bearer(token))).status).toBe(200);
  });

  it('refuses again once the step-up goes stale', async () => {
    const { token, sessionId } = await childOf(DEVICE_CODE);
    await Session.update(
      { stepUpVerifiedAt: new Date(Date.now() - 6 * 60_000), stepUpMethod: 'totp' },
      { where: { id: sessionId } },
    );

    const res = await request(app).post('/totp/enroll/start').set(bearer(token));

    expect(res.status).toBe(403);
    expect(res.body).toMatchObject({ error: 'step_up_required', fresh: false, method: 'totp' });
  });

  it.each([
    ['post', '/totp/enroll/start'],
    ['post', '/totp/enroll/verify'],
    ['post', '/totp/disable'],
    ['get', '/webauthn/register/start'],
    ['post', '/webauthn/register/finish'],
    ['post', '/recovery-codes'],
    ['delete', '/users/credentials'],
    ['post', '/registration/phone'],
    ['post', '/registration/phone/verify'],
    ['delete', `/recovery/requests/${randomUUID()}`],
  ] as ['post' | 'get' | 'delete', string][])(
    'answers step_up_required on %s %s, before reading the request',
    async (method, url) => {
      const { token } = await childOf(DEVICE_CODE);

      expectStepUpRequired(await request(app)[method](url).set(bearer(token)));
    },
  );

  it('does not delete a credential', async () => {
    const { Credential } = await import('../../src/models/credentials.js');
    const { user, token } = await childOf(DEVICE_CODE);
    const seed = (id: string) =>
      Credential.create({
        id,
        userId: user.id,
        publicKey: Buffer.from('key'),
        counter: 0,
        transports: [],
        deviceType: 'singleDevice',
        backedup: false,
      } as never);
    const id = `cred-${randomUUID()}`;
    await seed(id);
    await seed(`cred-${randomUUID()}`);

    expectStepUpRequired(
      await request(app).delete('/users/credentials').set(bearer(token)).send({ id }),
    );

    expect(await Credential.count({ where: { userId: user.id } })).toBe(2);
  });

  it('does not change the phone on the account', async () => {
    const { user, token } = await childOf(DEVICE_CODE);

    expectStepUpRequired(
      await request(app)
        .post('/registration/phone')
        .set(bearer(token))
        .send({ phone: '+14155550123' }),
    );

    await user.reload();
    expect(user.phone).toBeNull();
  });

  it('does not change a loopback child, with a step-up or without one', async () => {
    const { token } = await childOf(AUTHORIZATION_CODE);
    expect((await request(app).post('/totp/enroll/start').set(bearer(token))).status).toBe(200);
    expect((await request(app).post('/recovery-codes').set(bearer(token)).send({})).status).toBe(
      201,
    );

    const { client, parent } = await signedInToCli();
    const { token: subject } = await signSubject(client, parent);
    const plain = await exchange(subject);
    expect(
      (await request(app).post('/totp/enroll/start').set(bearer(plain.body.token))).status,
    ).toBe(200);
  });

  it('does not change a first-party session', async () => {
    const user = await createUser();
    const session = await createSession(user.id);
    const token = await accessTokenFor(session);

    expect((await request(app).post('/totp/enroll/start').set(bearer(token))).status).toBe(200);
    expect((await request(app).post('/recovery-codes').set(bearer(token)).send({})).status).toBe(
      201,
    );
    expect((await request(app).get('/webauthn/register/start').set(bearer(token))).status).toBe(
      200,
    );
  });

  it('cannot turn a device child into a parent for another exchange', async () => {
    const { client, parent } = await signedInToCli();
    const { token: first } = await signSubject(client, parent, { grantType: DEVICE_CODE });
    const child = await exchange(first);
    await store.bindOidcSession(child.body.sessionId, parent.userId, client.id);
    await store.upsertOidcPayload('Grant', randomUUID(), {
      payload: { accountId: parent.userId, clientId: client.id },
      expiresIn: 3600,
      sessionId: child.body.sessionId,
    });

    const childRow = await Session.findByPk(child.body.sessionId);
    const { token: second } = await signSubject(client, childRow as Session);
    const res = await exchange(second);

    expect(res.status).toBe(400);
    expect(res.body).toEqual(TOKEN_FAILURE);
  });

  it('keeps the child and its device grant on an organization switch', async () => {
    const { Organization } = await import('../../src/models/organizations.js');
    const { OrganizationMembership } = await import('../../src/models/organizationMemberships.js');
    const { user, token, sessionId } = await childOf(DEVICE_CODE);
    const organization = await Organization.create({
      name: 'Org',
      slug: `org-${randomUUID()}`,
    } as never);
    await OrganizationMembership.create({
      userId: user.id,
      organizationId: organization.id,
      roles: ['member'],
      scopes: [],
    } as never);

    const res = await request(app)
      .post(`/organizations/${organization.id}/switch`)
      .set(bearer(token));

    expect(res.status).toBe(200);
    expect(res.body.sessionId).toBe(sessionId);
    expectStepUpRequired(await adminRead(res.body.token));
  });
});
