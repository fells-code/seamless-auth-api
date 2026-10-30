import { Application } from 'express';
import request from 'supertest';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/models/oidcPayloads.js', () => ({
  OidcPayload: { destroy: vi.fn() },
}));

vi.mock('../../../src/services/oidcPayloadStore.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/services/oidcPayloadStore.js')>()),
  upsertOidcPayload: vi.fn(),
  findOidcPayload: vi.fn(),
  findOidcPayloadByUid: vi.fn(),
  findOidcPayloadByUserCode: vi.fn(),
  consumeOidcPayload: vi.fn(),
  destroyOidcPayload: vi.fn(),
  revokeOidcPayloadsByGrant: vi.fn(),
}));

vi.mock('../../../src/services/oidcSigning.js', () => ({
  signForOidcEdge: vi.fn(),
}));

vi.mock('../../../src/services/oidcProviderKeys.js', () => ({
  getOidcPublicJwks: vi.fn(),
  hasOidcProviderKeys: vi.fn(),
}));

vi.mock('../../../src/services/oidcClientRegistry.js', () => ({
  getOidcClientMetadata: vi.fn(),
  verifyOidcClientSecret: vi.fn(),
  getOidcAccountClaims: vi.fn(),
}));

vi.mock('../../../src/services/oidcAuthContext.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/services/oidcAuthContext.js')>()),
  getOidcAuthContext: vi.fn(),
}));

import { createApp } from '../../../src/app';
import { getSystemConfig } from '../../../src/config/getSystemConfig';
import { OidcPayload } from '../../../src/models/oidcPayloads.js';
import { Session } from '../../../src/models/sessions.js';
import { AuthEventService } from '../../../src/services/authEventService.js';
import { getOidcAuthContext } from '../../../src/services/oidcAuthContext.js';
import {
  getOidcAccountClaims,
  getOidcClientMetadata,
  verifyOidcClientSecret,
} from '../../../src/services/oidcClientRegistry.js';
import {
  consumeOidcPayload,
  destroyOidcPayload,
  findOidcPayload,
  findOidcPayloadByUid,
  ExpiryTooLongError,
  findOidcPayloadByUserCode,
  InvalidSessionIdError,
  revokeOidcPayloadsByGrant,
  upsertOidcPayload,
} from '../../../src/services/oidcPayloadStore.js';
import { getOidcPublicJwks } from '../../../src/services/oidcProviderKeys.js';
import { signForOidcEdge } from '../../../src/services/oidcSigning.js';
import { revokeSessionChain } from '../../../src/services/sessionService.js';
import { buildSystemConfig } from '../../factories/systemConfigFactory';
import { mintInternalServiceToken } from '../../factories/serviceTokenFactory';

const SESSION = '11111111-1111-4111-8111-111111111111';
const ISSUER = 'https://login.example.com';
const USER = '22222222-2222-4222-8222-222222222222';

let app: Application;
let token: string;

const record = {
  payload: { a: 1 },
  sessionId: null,
  expiresAt: '2030-01-01T00:00:00.000Z',
  consumedAt: null,
};

function edge(method: 'get' | 'put' | 'post' | 'delete', path: string) {
  return request(app)[method](path).set('x-seamless-service-token', token);
}

beforeAll(async () => {
  app = await createApp();
});

beforeEach(async () => {
  token = await mintInternalServiceToken();
  vi.mocked(getSystemConfig).mockResolvedValue(
    buildSystemConfig({
      oidc_provider_enabled: true,
      oidc_issuer: ISSUER,
      allow_client_secrets: false,
      third_party_clients_enabled: false,
    }),
  );
  (Session as unknown as { findByPk: unknown }).findByPk = vi.fn();
});

describe('the /oidc/* guard', () => {
  it('refuses a request without the service token', async () => {
    const res = await request(app).get('/oidc/config');

    expect(res.status).toBe(401);
    expect(res.body).toEqual({ error: 'invalid_service_token' });
  });

  it('refuses a token from the wrong issuer', async () => {
    token = await mintInternalServiceToken({ iss: 'someone-else' });
    expect((await edge('get', '/oidc/config')).status).toBe(401);
  });

  it('accepts the token with a Bearer prefix', async () => {
    const res = await request(app)
      .get('/oidc/config')
      .set('x-seamless-service-token', `Bearer ${token}`);

    expect(res.status).toBe(200);
  });

  it('answers 404 before checking the token while the provider is off', async () => {
    vi.mocked(getSystemConfig).mockResolvedValue(
      buildSystemConfig({ oidc_provider_enabled: false }),
    );

    const res = await request(app).get('/oidc/config');
    expect(res.status).toBe(404);
    expect(res.body).toEqual({ error: 'Not Found' });
  });

  it('answers like an unknown route while the provider is off', async () => {
    vi.mocked(getSystemConfig).mockResolvedValue(
      buildSystemConfig({ oidc_provider_enabled: false }),
    );

    const res = await edge('get', '/oidc/config');
    expect(res.status).toBe(404);
    expect(res.body).toEqual({ error: 'Not Found' });
  });

  it('treats an enabled provider with no issuer as off', async () => {
    vi.mocked(getSystemConfig).mockResolvedValue(
      buildSystemConfig({ oidc_provider_enabled: true, oidc_issuer: null }),
    );
    expect((await edge('get', '/oidc/jwks')).status).toBe(404);
  });
});

describe('GET /oidc/config', () => {
  it('reports the contract version and provider settings', async () => {
    const res = await edge('get', '/oidc/config');

    expect(res.body).toEqual({
      contractVersion: 1,
      issuer: ISSUER,
      appName: 'SeamlessAuth',
      allowClientSecrets: false,
      thirdPartyClientsEnabled: false,
    });
  });
});

describe('/oidc/payloads', () => {
  it('stores a record', async () => {
    vi.mocked(upsertOidcPayload).mockResolvedValue({ created: true });

    const res = await edge('put', '/oidc/payloads/Grant/g1').send({
      payload: { grantId: 'g1' },
      expiresIn: 60,
    });

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ created: true });
    expect(upsertOidcPayload).toHaveBeenCalledWith('Grant', 'g1', {
      payload: { grantId: 'g1' },
      expiresIn: 60,
    });
  });

  it('refuses an unknown model', async () => {
    const res = await edge('put', '/oidc/payloads/Client/c1').send({ payload: {}, expiresIn: 60 });
    expect(res.status).toBe(400);
  });

  it('answers 400 for a malformed session id', async () => {
    vi.mocked(upsertOidcPayload).mockRejectedValue(new InvalidSessionIdError());

    const res = await edge('put', '/oidc/payloads/Session/s1').send({
      payload: {},
      expiresIn: 60,
      sessionId: 'nope',
    });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_session_id');
  });

  it('answers 400 for too long an expiry', async () => {
    vi.mocked(upsertOidcPayload).mockRejectedValue(new ExpiryTooLongError());

    const res = await edge('put', '/oidc/payloads/Session/s1').send({ payload: {}, expiresIn: 60 });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_expiry');
  });

  it('passes an unexpected store failure on', async () => {
    vi.mocked(upsertOidcPayload).mockRejectedValue(new Error('db down'));

    const res = await edge('put', '/oidc/payloads/Session/s1').send({ payload: {}, expiresIn: 60 });
    expect(res.status).toBe(500);
  });

  it.each([
    ['/oidc/payloads/Grant/g1', findOidcPayload, ['Grant', 'g1']],
    [
      '/oidc/payloads/DeviceCode/by-user-code/ABCD',
      findOidcPayloadByUserCode,
      ['DeviceCode', 'ABCD'],
    ],
    ['/oidc/payloads/Interaction/by-uid/u1', findOidcPayloadByUid, ['Interaction', 'u1']],
  ] as const)('reads %s', async (path, finder, args) => {
    vi.mocked(finder).mockResolvedValueOnce(record);
    const found = await edge('get', path);
    expect(found.status).toBe(200);
    expect(found.body).toEqual(record);
    expect(finder).toHaveBeenCalledWith(...args);

    vi.mocked(finder).mockResolvedValueOnce(null);
    expect((await edge('get', path)).status).toBe(404);
  });

  it('consumes, destroys and revokes by grant', async () => {
    expect((await edge('post', '/oidc/payloads/AuthorizationCode/c1/consume')).status).toBe(204);
    expect((await edge('delete', '/oidc/payloads/Session/s1')).status).toBe(204);
    expect((await edge('delete', '/oidc/payloads/RefreshToken/by-grant/g1')).status).toBe(204);

    expect(consumeOidcPayload).toHaveBeenCalledWith('AuthorizationCode', 'c1');
    expect(destroyOidcPayload).toHaveBeenCalledWith('Session', 's1');
    expect(revokeOidcPayloadsByGrant).toHaveBeenCalledWith('RefreshToken', 'g1');
  });
});

describe('POST /oidc/sign', () => {
  const body = {
    kind: 'id_token',
    kid: 'k1',
    clientId: 'app',
    sessionId: SESSION,
    signingInput: 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1In0',
  };

  it('returns the signature', async () => {
    vi.mocked(signForOidcEdge).mockResolvedValue({ ok: true, kid: 'k1', signature: 'c2ln' });

    const res = await edge('post', '/oidc/sign').send(body);

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ kid: 'k1', signature: 'c2ln' });
  });

  it('answers 403 with the refusal code and audits it', async () => {
    vi.mocked(signForOidcEdge).mockResolvedValue({
      ok: false,
      code: 'auth_context_mismatch',
      userId: 'user-1',
    });

    const res = await edge('post', '/oidc/sign').send(body);

    expect(res.status).toBe(403);
    expect(res.body).toEqual({ error: 'auth_context_mismatch' });
    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'oidc_sign_failed',
        userId: 'user-1',
        sessionId: SESSION,
        metadata: { reason: 'auth_context_mismatch', kind: 'id_token', clientId: 'app' },
      }),
    );
  });

  it('answers 400 for a malformed signing input', async () => {
    vi.mocked(signForOidcEdge).mockResolvedValue({ ok: false, code: 'malformed_signing_input' });

    const res = await edge('post', '/oidc/sign').send({
      ...body,
      kind: 'client_credentials',
      sessionId: undefined,
    });

    expect(res.status).toBe(400);
    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({ userId: null, sessionId: null }),
    );
  });

  it('refuses a user token request without a session before signing', async () => {
    const res = await edge('post', '/oidc/sign').send({ ...body, sessionId: undefined });

    expect(res.status).toBe(400);
    expect(signForOidcEdge).not.toHaveBeenCalled();
  });
});

describe('keys, clients and accounts', () => {
  it('publishes the provider JWKS', async () => {
    const jwks = {
      activeKid: 'k1',
      keys: [{ kty: 'RSA', kid: 'k1', alg: 'RS256', use: 'sig', n: 'n', e: 'AQAB' }],
    };
    vi.mocked(getOidcPublicJwks).mockReturnValue(jwks);

    expect((await edge('get', '/oidc/jwks')).body).toEqual(jwks);
  });

  it('returns client metadata, or 404', async () => {
    const metadata = {
      client_id: 'app',
      client_name: 'App',
      application_type: 'web' as const,
      token_endpoint_auth_method: 'none' as const,
      grant_types: ['authorization_code' as const],
      response_types: ['code' as const],
      redirect_uris: ['https://app.example.com/cb'],
      post_logout_redirect_uris: [],
      'urn:seamless:first_party': true,
    };
    vi.mocked(getOidcClientMetadata).mockResolvedValueOnce(metadata);
    expect((await edge('get', '/oidc/clients/app')).body).toEqual(metadata);

    vi.mocked(getOidcClientMetadata).mockResolvedValueOnce(null);
    expect((await edge('get', '/oidc/clients/app')).status).toBe(404);
  });

  it('verifies a client secret', async () => {
    vi.mocked(verifyOidcClientSecret).mockResolvedValue(false);

    const res = await edge('post', '/oidc/clients/app/verify-secret').send({ secret: 's' });

    expect(res.body).toEqual({ valid: false });
    expect(verifyOidcClientSecret).toHaveBeenCalledWith('app', 's');
  });

  it('returns account claims, or 404', async () => {
    const claims = { sub: 'u1', roles: [], org_id: null };
    vi.mocked(getOidcAccountClaims).mockResolvedValueOnce(claims);
    expect((await edge('get', '/oidc/accounts/u1')).body).toEqual(claims);

    vi.mocked(getOidcAccountClaims).mockResolvedValueOnce(null);
    expect((await edge('get', '/oidc/accounts/u1')).status).toBe(404);
  });
});

describe('sessions', () => {
  it('returns the auth context, or 404', async () => {
    const context = {
      sessionId: SESSION,
      userId: 'u1',
      active: true,
      recovery: false,
      authMethods: [],
      authTime: 1,
      acr: null,
      amr: [],
    };
    vi.mocked(getOidcAuthContext).mockResolvedValueOnce(context);
    expect((await edge('get', `/oidc/sessions/${SESSION}/auth-context`)).body).toEqual(context);

    vi.mocked(getOidcAuthContext).mockResolvedValueOnce(null);
    expect((await edge('get', `/oidc/sessions/${SESSION}/auth-context`)).status).toBe(404);
  });

  it('revokes the chain and the provider records behind it', async () => {
    const session = { id: SESSION, userId: 'u1' };
    vi.mocked(Session.findByPk).mockResolvedValue(session as never);

    const res = await edge('post', `/oidc/sessions/${SESSION}/revoke`).send({
      reason: 'refresh_token_reuse',
      correlationId: 'c1',
    });

    expect(res.status).toBe(204);
    expect(revokeSessionChain).toHaveBeenCalledWith(session, 'oidc_refresh_token_reuse');
    expect(OidcPayload.destroy).toHaveBeenCalledWith({ where: { sessionId: SESSION } });
    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'oidc_session_revoked',
        metadata: { reason: 'refresh_token_reuse', correlationId: 'c1' },
      }),
    );
  });

  it('answers 404 for an unknown or malformed session', async () => {
    vi.mocked(Session.findByPk).mockResolvedValue(null);
    expect(
      (await edge('post', `/oidc/sessions/${SESSION}/revoke`).send({ reason: 'provider_logout' }))
        .status,
    ).toBe(404);

    expect(
      (await edge('post', '/oidc/sessions/nope/revoke').send({ reason: 'provider_logout' })).status,
    ).toBe(404);
    expect(AuthEventService.log).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: 'oidc_session_revoked', metadata: expect.anything() }),
    );
  });
});

describe('POST /oidc/events', () => {
  it('records the event under its auth event type', async () => {
    vi.mocked(Session.findByPk).mockResolvedValue({ id: SESSION, userId: USER } as never);

    const res = await edge('post', '/oidc/events').send({
      type: 'refresh_token_suspicious',
      correlationId: 'c1',
      occurredAt: '2026-10-30T12:00:00.000Z',
      clientId: 'app',
      userId: USER,
      sessionId: SESSION,
      grantId: 'g1',
      metadata: { note: 'x' },
    });

    expect(res.status).toBe(202);
    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'oidc_refresh_token_suspicious',
        userId: USER,
        sessionId: SESSION,
        metadata: {
          note: 'x',
          correlationId: 'c1',
          occurredAt: '2026-10-30T12:00:00.000Z',
          clientId: 'app',
          grantId: 'g1',
        },
      }),
    );
  });

  it('refuses a user the session does not belong to, or a user without a session', async () => {
    vi.mocked(Session.findByPk).mockResolvedValue({ id: SESSION, userId: 'someone-else' } as never);
    const event = {
      type: 'token_issued',
      correlationId: 'c1',
      occurredAt: '2026-10-30T12:00:00.000Z',
      userId: USER,
    };

    expect((await edge('post', '/oidc/events').send({ ...event, sessionId: SESSION })).status).toBe(
      400,
    );
    expect((await edge('post', '/oidc/events').send(event)).status).toBe(400);
    expect(AuthEventService.log).not.toHaveBeenCalled();
  });

  it('drops ids that are not ids rather than fail the audit write', async () => {
    await edge('post', '/oidc/events').send({
      type: 'edge_failed',
      correlationId: 'c1',
      occurredAt: '2026-10-30T12:00:00.000Z',
      userId: 'u1',
      sessionId: 'nope',
    });

    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({ userId: null, sessionId: null }),
    );
  });

  it('records an event with no subject', async () => {
    await edge('post', '/oidc/events').send({
      type: 'edge_failed',
      correlationId: 'c1',
      occurredAt: '2026-10-30T12:00:00.000Z',
    });

    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'oidc_edge_failed',
        userId: null,
        sessionId: null,
        metadata: expect.objectContaining({ clientId: null, grantId: null }),
      }),
    );
  });
});
