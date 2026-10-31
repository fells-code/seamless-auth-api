import { randomUUID } from 'crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { getSequelize, initializeModels } from '../../src/models/index.js';
import { OidcClient } from '../../src/models/oidcClients.js';
import { OidcPayload } from '../../src/models/oidcPayloads.js';
import {
  claimOAuthStateUse,
  consumeOidcPayload,
  findGrantBoundSession,
  findOidcPayload,
  findOidcPayloadByUid,
  purgeExpiredOidcPayloads,
  revokeOidcPayloadsByGrant,
  upsertOidcPayload,
} from '../../src/services/oidcPayloadStore.js';

beforeAll(async () => {
  await initializeModels();
});

afterAll(async () => {
  await getSequelize().close();
});

describe('oidc_payloads', () => {
  it('stores, finds, consumes and revokes by grant', async () => {
    const id = randomUUID();
    const grantId = randomUUID();

    await upsertOidcPayload('AuthorizationCode', id, {
      payload: { grantId, uid: `uid-${id}`, nested: { a: [1, 2] } },
      expiresIn: 600,
    });

    expect((await findOidcPayload('AuthorizationCode', id))?.payload).toEqual({
      grantId,
      uid: `uid-${id}`,
      nested: { a: [1, 2] },
    });
    expect(await findOidcPayloadByUid('AuthorizationCode', `uid-${id}`)).not.toBeNull();

    await consumeOidcPayload('AuthorizationCode', id);
    const consumed = await findOidcPayload('AuthorizationCode', id);
    expect(consumed?.consumedAt).not.toBeNull();

    await consumeOidcPayload('AuthorizationCode', id);
    expect((await findOidcPayload('AuthorizationCode', id))?.consumedAt).toBe(consumed?.consumedAt);

    await revokeOidcPayloadsByGrant('AuthorizationCode', grantId);
    expect(await findOidcPayload('AuthorizationCode', id)).toBeNull();
  });

  it('overwrites a record on upsert without losing its consumed state', async () => {
    const id = randomUUID();

    await upsertOidcPayload('Session', id, { payload: { v: 1 }, expiresIn: 600 });
    await consumeOidcPayload('Session', id);
    await upsertOidcPayload('Session', id, { payload: { v: 2 }, expiresIn: 600 });

    const found = await findOidcPayload('Session', id);
    expect(found?.payload).toEqual({ v: 2 });
    expect(found?.consumedAt).not.toBeNull();
  });

  it('keeps the same id apart across models', async () => {
    const id = randomUUID();

    await upsertOidcPayload('Grant', id, { payload: { m: 'grant' }, expiresIn: 600 });
    await upsertOidcPayload('Session', id, { payload: { m: 'session' }, expiresIn: 600 });

    expect((await findOidcPayload('Grant', id))?.payload).toEqual({ m: 'grant' });
    expect((await findOidcPayload('Session', id))?.payload).toEqual({ m: 'session' });
  });

  it('claims an OAuth state once across concurrent callers, apart from the edge models', async () => {
    const hash = randomUUID();
    const expiresAt = new Date(Date.now() + 600_000);

    const results = await Promise.all([
      claimOAuthStateUse(hash, expiresAt),
      claimOAuthStateUse(hash, expiresAt),
      claimOAuthStateUse(hash, expiresAt),
    ]);

    expect(results.filter(Boolean)).toHaveLength(1);
    expect(await claimOAuthStateUse(hash, expiresAt)).toBe(false);
    expect(await findOidcPayload('ReplayDetection', hash)).toBeNull();
    expect(await OidcPayload.count({ where: { model: 'OAuthStateReplay', id: hash } })).toBe(1);
  });

  it('lets an expired OAuth state row be claimed again', async () => {
    const hash = randomUUID();

    expect(await claimOAuthStateUse(hash, new Date(Date.now() - 1000))).toBe(true);
    expect(await claimOAuthStateUse(hash, new Date(Date.now() + 600_000))).toBe(true);
    expect(await claimOAuthStateUse(hash, new Date(Date.now() + 600_000))).toBe(false);
  });

  it('inserts replay detection only once, in one statement', async () => {
    const id = randomUUID();
    const write = () =>
      upsertOidcPayload('ReplayDetection', id, { payload: { iss: 'x' }, expiresIn: 600 });

    const results = await Promise.all([write(), write(), write()]);

    expect(results.filter((result) => result.created)).toHaveLength(1);
  });

  it('lets an expired replay row be taken over', async () => {
    const id = randomUUID();

    await OidcPayload.create({
      id,
      model: 'ReplayDetection',
      payload: {},
      expiresAt: new Date(Date.now() - 1000),
    });

    expect(await upsertOidcPayload('ReplayDetection', id, { payload: {}, expiresIn: 600 })).toEqual(
      { created: true },
    );
  });

  it('hides and purges expired records', async () => {
    const id = randomUUID();

    await OidcPayload.create({
      id,
      model: 'Grant',
      payload: {},
      expiresAt: new Date(Date.now() - 1000),
    });

    expect(await findOidcPayload('Grant', id)).toBeNull();
    expect(await purgeExpiredOidcPayloads()).toBeGreaterThanOrEqual(1);
    expect(await OidcPayload.findOne({ where: { model: 'Grant', id } })).toBeNull();
  });
});

describe('grant binding', () => {
  it('finds a session only through a grant for the same client', async () => {
    const { User } = await import('../../src/models/users.js');
    const { Session } = await import('../../src/models/sessions.js');
    const user = await User.create({ email: `${randomUUID()}@example.com` } as never);
    const session = await Session.create({
      userId: user.id,
      mode: 'server',
      expiresAt: new Date(Date.now() + 3_600_000),
      idleExpiresAt: new Date(Date.now() + 3_600_000),
    });

    expect(await findGrantBoundSession(session.id, 'app')).toBeNull();

    await upsertOidcPayload('Grant', randomUUID(), {
      payload: { clientId: 'app', accountId: user.id },
      expiresIn: 600,
      sessionId: session.id,
    });

    expect((await findGrantBoundSession(session.id, 'app'))?.id).toBe(session.id);
    expect(await findGrantBoundSession(session.id, 'other')).toBeNull();
  });

  it('binds every client a session signed in to, not just one of them', async () => {
    const { User } = await import('../../src/models/users.js');
    const { Session } = await import('../../src/models/sessions.js');
    const user = await User.create({ email: `${randomUUID()}@example.com` } as never);
    const session = await Session.create({
      userId: user.id,
      mode: 'server',
      expiresAt: new Date(Date.now() + 3_600_000),
      idleExpiresAt: new Date(Date.now() + 3_600_000),
    });

    for (const clientId of ['first', 'second', 'third']) {
      await upsertOidcPayload('Grant', randomUUID(), {
        payload: { clientId, accountId: user.id },
        expiresIn: 600,
        sessionId: session.id,
      });
    }

    for (const clientId of ['first', 'second', 'third']) {
      expect((await findGrantBoundSession(session.id, clientId))?.id).toBe(session.id);
    }
    expect(await findGrantBoundSession(session.id, 'other')).toBeNull();
  });
});

describe('step-up auth context', () => {
  it('reports a step-up on the refreshed row for the session the provider recorded', async () => {
    const { User } = await import('../../src/models/users.js');
    const { Session } = await import('../../src/models/sessions.js');
    const { recordStepUpVerification } = await import('../../src/services/stepUpService.js');
    const { getOidcAuthContext } = await import('../../src/services/oidcAuthContext.js');
    const user = await User.create({ email: `${randomUUID()}@example.com` } as never);
    const signedInAt = new Date(Date.now() - 600_000);
    const times = {
      userId: user.id,
      mode: 'server' as const,
      expiresAt: new Date(Date.now() + 3_600_000),
      idleExpiresAt: new Date(Date.now() + 3_600_000),
      authMethods: [{ method: 'email_otp' as const, at: signedInAt.toISOString() }],
      authTime: signedInAt,
    };
    const recorded = await Session.create(times);
    const current = await Session.create(times);
    await recorded.update({ replacedBySessionId: current.id });

    const verifiedAt = new Date(Math.floor(Date.now() / 1000) * 1000);
    await recordStepUpVerification({
      sessionId: current.id,
      userId: user.id,
      method: 'webauthn',
      passkey: { deviceBound: false, userVerified: true },
      verifiedAt,
    });

    expect(await getOidcAuthContext(recorded.id)).toMatchObject({
      sessionId: recorded.id,
      active: true,
      authTime: verifiedAt.getTime() / 1000,
      acr: 'phr',
      amr: ['swk', 'user', 'otp', 'mfa'],
    });
  });
});

describe('oidc_clients', () => {
  it('refuses a public client with a token endpoint auth method', async () => {
    await expect(
      OidcClient.create({
        id: randomUUID(),
        name: 'Bad',
        clientType: 'public',
        tokenEndpointAuthMethod: 'private_key_jwt',
      }),
    ).rejects.toThrow();
  });

  it('refuses client_secret_jwt', async () => {
    await expect(
      OidcClient.create({
        id: randomUUID(),
        name: 'Bad',
        clientType: 'confidential',
        tokenEndpointAuthMethod: 'client_secret_jwt' as never,
      }),
    ).rejects.toThrow();
  });

  it('stores a confidential client with defaults', async () => {
    const client = await OidcClient.create({
      id: randomUUID(),
      name: 'Grafana',
      clientType: 'confidential',
      tokenEndpointAuthMethod: 'private_key_jwt',
    });
    const reloaded = await OidcClient.findByPk(client.id);

    expect(reloaded?.grantTypes).toEqual(['authorization_code', 'refresh_token']);
    expect(reloaded?.firstParty).toBe(false);
    expect(reloaded?.deviceFlowEnabled).toBe(false);
  });
});
