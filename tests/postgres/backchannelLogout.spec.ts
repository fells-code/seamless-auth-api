import { generateKeyPairSync, randomUUID } from 'crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const ISSUER = 'https://login.example.com';

vi.mock('../../src/lib/oauthProviderPolicy.js', () => ({
  providerFetch: vi.fn(async () => ({ status: 204, body: null })),
}));

vi.mock('../../src/services/oidcProviderKeys.js', () => ({
  getOidcPublicJwks: () => ({ activeKid: 'k1', keys: [] }),
  getActiveOidcSigningKey: () => privateKey,
}));

vi.mock('../../src/config/getSystemConfig.js', () => ({
  getSystemConfig: async () => ({ oidc_issuer: ISSUER, third_party_clients_enabled: false }),
}));

import { providerFetch } from '../../src/lib/oauthProviderPolicy.js';
import { AuthEvent } from '../../src/models/authEvents.js';
import { getSequelize, initializeModels } from '../../src/models/index.js';
import { OidcClient } from '../../src/models/oidcClients.js';
import { OidcPayload } from '../../src/models/oidcPayloads.js';
import { Session } from '../../src/models/sessions.js';
import { User } from '../../src/models/users.js';
import {
  BACKCHANNEL_LOGOUT_MODEL,
  sendBackchannelLogout,
} from '../../src/services/oidcBackchannelLogout.js';
import {
  bindOidcSession,
  destroyOidcPayload,
  upsertOidcPayload,
} from '../../src/services/oidcPayloadStore.js';

function claimsOf(body: URLSearchParams) {
  const token = body.get('logout_token')!;
  return JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString());
}

beforeAll(async () => {
  await initializeModels();
});

afterAll(async () => {
  await getSequelize().close();
});

beforeEach(() => {
  vi.mocked(providerFetch).mockClear();
});

async function signedInToTwoApps() {
  const user = await User.create({ email: `${randomUUID()}@example.com` } as never);
  const session = await Session.create({
    userId: user.id,
    mode: 'server',
    expiresAt: new Date(Date.now() + 3_600_000),
    idleExpiresAt: new Date(Date.now() + 3_600_000),
  });

  const apps = [`kept-${randomUUID()}`, `left-${randomUUID()}`];
  const grants: Record<string, string> = {};
  for (const id of apps) {
    await OidcClient.create({
      id,
      name: id,
      firstParty: true,
      clientType: 'public',
      tokenEndpointAuthMethod: 'none',
      redirectUris: ['https://app.example.com/cb'],
      backchannelLogoutUri: `https://${id}.example.com/logout`,
    });
    grants[id] = randomUUID();
    await upsertOidcPayload('Grant', grants[id], {
      payload: { clientId: id, accountId: user.id },
      expiresIn: 600,
      sessionId: session.id,
    });
    await bindOidcSession(session.id, user.id, id);
  }

  await upsertOidcPayload('Session', randomUUID(), {
    payload: {
      accountId: user.id,
      authorizations: { [apps[0]]: { sid: 'sid-kept' }, [apps[1]]: { sid: 'sid-left' } },
    },
    expiresIn: 600,
    sessionId: session.id,
  });

  return { user, session, kept: apps[0], left: apps[1], grants };
}

describe('back-channel logout when one application grant ends', () => {
  it('tells only the application whose grant ended, while the session lives on', async () => {
    const { user, session, kept, left, grants } = await signedInToTwoApps();

    await destroyOidcPayload('Grant', grants[left]);

    expect(providerFetch).toHaveBeenCalledTimes(1);
    const [uri, init] = vi.mocked(providerFetch).mock.calls[0] as [string, RequestInit];
    expect(uri).toBe(`https://${left}.example.com/logout`);
    expect(claimsOf(init.body as URLSearchParams)).toMatchObject({
      iss: ISSUER,
      aud: left,
      sub: user.id,
      sid: 'sid-left',
    });

    const sent = await AuthEvent.findAll({
      where: { session_id: session.id, type: 'oidc_backchannel_logout_sent' },
    });
    expect(sent.map((event) => (event.metadata as { clientId: string }).clientId)).toEqual([left]);

    expect(
      await OidcPayload.findOne({
        where: { model: BACKCHANNEL_LOGOUT_MODEL, id: `${session.id}:${kept}` },
      }),
    ).not.toBeNull();
    await session.reload();
    expect(session.revokedAt).toBeNull();

    // When the session itself ends later, only the application still signed in is told.
    vi.mocked(providerFetch).mockClear();
    await sendBackchannelLogout([session.id]);
    expect(vi.mocked(providerFetch).mock.calls.map(([target]) => target)).toEqual([
      `https://${kept}.example.com/logout`,
    ]);
  });

  it('sends nothing when a grant without a recorded sign-in ends', async () => {
    const { session, kept } = await signedInToTwoApps();
    const stray = randomUUID();
    await upsertOidcPayload('Grant', stray, {
      payload: { clientId: kept },
      expiresIn: 600,
    });

    await destroyOidcPayload('Grant', stray);
    await destroyOidcPayload('Grant', randomUUID());

    expect(providerFetch).not.toHaveBeenCalled();
    expect(
      await OidcPayload.count({
        where: { model: BACKCHANNEL_LOGOUT_MODEL, sessionId: session.id },
      }),
    ).toBe(2);
  });
});
