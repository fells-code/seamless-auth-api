import { Application } from 'express';
import request from 'supertest';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/models/oidcClients.js', () => ({
  OidcClient: {
    findAll: vi.fn(),
    findByPk: vi.fn(),
    create: vi.fn(),
    sequelize: { transaction: vi.fn(async (fn: (tx: unknown) => unknown) => fn({ tx: true })) },
  },
}));

vi.mock('../../../src/models/oidcClientResources.js', () => ({
  OidcClientResource: { destroy: vi.fn(), findAll: vi.fn() },
}));

vi.mock('../../../src/models/oidcPayloads.js', () => ({
  OidcPayload: { destroy: vi.fn() },
}));

import { createApp } from '../../../src/app';
import { getSystemConfig } from '../../../src/config/getSystemConfig';
import { OidcClientResource } from '../../../src/models/oidcClientResources.js';
import { OidcClient } from '../../../src/models/oidcClients.js';
import { OidcPayload } from '../../../src/models/oidcPayloads.js';
import { Session } from '../../../src/models/sessions.js';
import { AuthEventService } from '../../../src/services/authEventService.js';
import { createOidcClientSecretLookup } from '../../../src/services/oidcClientRegistry.js';
import { buildFreshStepUpSession } from '../../factories/sessionFactory';
import { buildSystemConfig } from '../../factories/systemConfigFactory';

const jwk = { kty: 'RSA', kid: 'k1', alg: 'RS256', n: 'abc', e: 'AQAB' };

let app: Application;

type Row = Record<string, unknown> & {
  update: ReturnType<typeof vi.fn>;
  destroy: ReturnType<typeof vi.fn>;
};

function row(overrides: Record<string, unknown> = {}): Row {
  const data: Row = {
    id: 'app-1',
    name: 'Grafana',
    clientType: 'confidential',
    firstParty: true,
    tokenEndpointAuthMethod: 'private_key_jwt',
    jwks: null,
    jwksUri: 'https://grafana.example.com/jwks',
    secretLookup: null,
    redirectUris: ['https://grafana.example.com/cb'],
    postLogoutRedirectUris: [],
    grantTypes: ['authorization_code', 'refresh_token'],
    backchannelLogoutUri: null,
    accessTokenTtlSeconds: null,
    idTokenTtlSeconds: null,
    refreshTokenTtlSeconds: null,
    deviceFlowEnabled: false,
    noticesEnabled: false,
    disabledAt: null,
    createdAt: new Date('2026-10-30T12:00:00.000Z'),
    updatedAt: new Date('2026-10-30T12:00:00.000Z'),
    ...overrides,
    update: vi.fn(async (changes: Record<string, unknown>) => Object.assign(data, changes)),
    destroy: vi.fn(),
  };
  return data;
}

function withConfig(overrides: Record<string, unknown> = {}) {
  vi.mocked(getSystemConfig).mockResolvedValue(
    buildSystemConfig({
      allow_client_secrets: false,
      third_party_clients_enabled: false,
      ...overrides,
    }) as never,
  );
}

function loggedTypes() {
  return vi.mocked(AuthEventService.log).mock.calls.map(([event]) => event.type);
}

beforeAll(async () => {
  app = await createApp();
});

beforeEach(() => {
  vi.clearAllMocks();
  vi.spyOn(AuthEventService, 'log').mockResolvedValue(undefined);
  (Session.findOne as ReturnType<typeof vi.fn>).mockResolvedValue(buildFreshStepUpSession());
  vi.mocked(OidcClient.create).mockImplementation(
    async (values: Record<string, unknown>) => row(values) as never,
  );
  withConfig();
});

describe('GET /admin/applications', () => {
  it('lists applications without secrets or the device grant URN', async () => {
    vi.mocked(OidcClient.findAll).mockResolvedValue([
      row({
        secretLookup: 'abc',
        tokenEndpointAuthMethod: 'client_secret_basic',
        jwksUri: null,
        grantTypes: ['refresh_token', 'urn:ietf:params:oauth:grant-type:device_code'],
        deviceFlowEnabled: true,
        redirectUris: ['http://127.0.0.1/cb'],
      }),
    ] as never);

    const res = await request(app).get('/admin/applications');

    expect(res.status).toBe(200);
    expect(res.body.applications[0]).toMatchObject({
      id: 'app-1',
      applicationType: 'native',
      hasSecret: true,
      grantTypes: ['refresh_token'],
      deviceFlowEnabled: true,
    });
    expect(JSON.stringify(res.body)).not.toContain('secretLookup');
  });
});

describe('GET /admin/applications/:id', () => {
  it('answers 404 for an unknown application', async () => {
    vi.mocked(OidcClient.findByPk).mockResolvedValue(null);

    const res = await request(app).get('/admin/applications/nope');

    expect(res.status).toBe(404);
    expect(res.body).toEqual({ error: 'Application not found' });
  });

  it('returns one application', async () => {
    vi.mocked(OidcClient.findByPk).mockResolvedValue(row() as never);

    const res = await request(app).get('/admin/applications/app-1');

    expect(res.status).toBe(200);
    expect(res.body.application).toMatchObject({ id: 'app-1', applicationType: 'web' });
  });
});

describe('POST /admin/applications', () => {
  it('creates a native public client with PKCE only and audits it', async () => {
    const res = await request(app)
      .post('/admin/applications')
      .send({
        name: 'Desktop',
        clientType: 'public',
        firstParty: true,
        redirectUris: ['http://127.0.0.1/callback', 'com.example.desktop:/callback'],
      });

    expect(res.status).toBe(201);
    expect(res.body.clientSecret).toBeUndefined();
    expect(res.body.application).toMatchObject({
      clientType: 'public',
      tokenEndpointAuthMethod: 'none',
      applicationType: 'native',
      hasSecret: false,
    });
    expect(OidcClient.create).toHaveBeenCalledWith(
      expect.objectContaining({ tokenEndpointAuthMethod: 'none', secretLookup: null }),
    );
    expect(vi.mocked(OidcClient.create).mock.calls[0][0].id).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(loggedTypes()).toEqual(['admin_oidc_application_created']);
  });

  it('defaults a confidential client to private_key_jwt', async () => {
    const res = await request(app)
      .post('/admin/applications')
      .send({
        name: 'Grafana',
        clientType: 'confidential',
        firstParty: true,
        redirectUris: ['https://grafana.example.com/cb'],
        jwks: { keys: [jwk] },
      });

    expect(res.status).toBe(201);
    expect(res.body.application.tokenEndpointAuthMethod).toBe('private_key_jwt');
    expect(res.body.application.jwks).toEqual({ keys: [jwk] });
  });

  it('stores the device grant for a first-party device client', async () => {
    const res = await request(app)
      .post('/admin/applications')
      .send({
        name: 'TV',
        clientType: 'public',
        firstParty: true,
        grantTypes: ['refresh_token'],
        deviceFlowEnabled: true,
      });

    expect(res.status).toBe(201);
    expect(OidcClient.create).toHaveBeenCalledWith(
      expect.objectContaining({
        grantTypes: ['refresh_token', 'urn:ietf:params:oauth:grant-type:device_code'],
      }),
    );
  });

  it('returns a shared secret once and stores only its HMAC', async () => {
    withConfig({ allow_client_secrets: true });

    const res = await request(app)
      .post('/admin/applications')
      .send({
        name: 'Legacy',
        clientType: 'confidential',
        firstParty: true,
        tokenEndpointAuthMethod: 'client_secret_basic',
        redirectUris: ['https://legacy.example.com/cb'],
      });

    expect(res.status).toBe(201);
    expect(res.body.clientSecret).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(res.body.application.hasSecret).toBe(true);
    const stored = vi.mocked(OidcClient.create).mock.calls[0][0].secretLookup;
    expect(stored).toBe(createOidcClientSecretLookup(res.body.clientSecret));
    const metadata = vi.mocked(AuthEventService.log).mock.calls.map(([event]) => event.metadata);
    expect(JSON.stringify(metadata)).not.toContain(res.body.clientSecret);
  });

  it('refuses a shared secret while allow_client_secrets is off', async () => {
    const res = await request(app)
      .post('/admin/applications')
      .send({
        name: 'Legacy',
        clientType: 'confidential',
        firstParty: true,
        tokenEndpointAuthMethod: 'client_secret_post',
        redirectUris: ['https://legacy.example.com/cb'],
      });

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/allow_client_secrets/);
    expect(OidcClient.create).not.toHaveBeenCalled();
  });

  it('refuses a third-party client while third_party_clients_enabled is off', async () => {
    const res = await request(app)
      .post('/admin/applications')
      .send({
        name: 'Partner',
        clientType: 'confidential',
        redirectUris: ['https://partner.example.com/cb'],
      });

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/third_party_clients_enabled/);
  });

  it('allows a third-party client once third-party clients are on', async () => {
    withConfig({ third_party_clients_enabled: true });

    const res = await request(app)
      .post('/admin/applications')
      .send({
        name: 'Partner',
        clientType: 'confidential',
        redirectUris: ['https://partner.example.com/cb'],
      });

    expect(res.status).toBe(201);
    expect(res.body.application.firstParty).toBe(false);
  });

  it.each([
    ['a localhost redirect', { redirectUris: ['http://localhost:3000/cb'] }],
    ['a public client with a secret method', { tokenEndpointAuthMethod: 'client_secret_basic' }],
    ['the implicit grant', { grantTypes: ['implicit'] }],
    ['client_credentials on a public client', { grantTypes: ['client_credentials'] }],
  ])('refuses %s with the validation body', async (_label, change) => {
    const res = await request(app)
      .post('/admin/applications')
      .send({
        name: 'Desktop',
        clientType: 'public',
        firstParty: true,
        redirectUris: ['http://127.0.0.1/cb'],
        ...change,
      });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_request');
    expect(OidcClient.create).not.toHaveBeenCalled();
  });
});

describe('PATCH /admin/applications/:id', () => {
  it('changes one field and audits what changed', async () => {
    const existing = row();
    vi.mocked(OidcClient.findByPk).mockResolvedValue(existing as never);

    const res = await request(app).patch('/admin/applications/app-1').send({ name: 'Renamed' });

    expect(res.status).toBe(200);
    expect(res.body.application.name).toBe('Renamed');
    expect(existing.update).toHaveBeenCalledWith(
      expect.objectContaining({
        name: 'Renamed',
        redirectUris: ['https://grafana.example.com/cb'],
      }),
    );
    expect(existing.update.mock.calls[0][0]).not.toHaveProperty('jwksUri');
    expect(vi.mocked(AuthEventService.log).mock.calls[0][0]).toMatchObject({
      type: 'admin_oidc_application_updated',
      metadata: { clientId: 'app-1', changed: ['name'], name: 'Renamed' },
    });
  });

  it('re-checks the merged result', async () => {
    vi.mocked(OidcClient.findByPk).mockResolvedValue(row() as never);

    const res = await request(app).patch('/admin/applications/app-1').send({ redirectUris: [] });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_request');
    expect(res.body.details.issues[0].path).toEqual(['redirectUris']);
  });

  it('refuses the device grant once a client is made third-party', async () => {
    withConfig({ third_party_clients_enabled: true });
    vi.mocked(OidcClient.findByPk).mockResolvedValue(
      row({
        deviceFlowEnabled: true,
        clientType: 'public',
        tokenEndpointAuthMethod: 'none',
        jwksUri: null,
      }) as never,
    );

    const res = await request(app).patch('/admin/applications/app-1').send({ firstParty: false });

    expect(res.status).toBe(400);
    expect(res.body.details.issues[0].path).toEqual(['deviceFlowEnabled']);
  });

  it('drops the keys when moving off private_key_jwt, and the secret when moving off a secret', async () => {
    withConfig({ allow_client_secrets: true });
    const existing = row();
    vi.mocked(OidcClient.findByPk).mockResolvedValue(existing as never);

    const toSecret = await request(app)
      .patch('/admin/applications/app-1')
      .send({ tokenEndpointAuthMethod: 'client_secret_basic' });

    expect(toSecret.status).toBe(200);
    expect(existing.update).toHaveBeenLastCalledWith(
      expect.objectContaining({ jwks: null, jwksUri: null }),
    );

    existing.secretLookup = 'abc';
    const toKeys = await request(app)
      .patch('/admin/applications/app-1')
      .send({ tokenEndpointAuthMethod: 'private_key_jwt' });

    expect(toKeys.status).toBe(200);
    expect(existing.update).toHaveBeenLastCalledWith(
      expect.objectContaining({ secretLookup: null }),
    );
  });

  it('does not re-check instance flags the patch does not touch', async () => {
    vi.mocked(OidcClient.findByPk).mockResolvedValue(
      row({
        firstParty: false,
        tokenEndpointAuthMethod: 'client_secret_basic',
        jwksUri: null,
      }) as never,
    );

    const res = await request(app).patch('/admin/applications/app-1').send({ name: 'Renamed' });

    expect(res.status).toBe(200);
  });

  it('disables and re-enables an application, keeping the first disable time', async () => {
    const disabledAt = new Date('2026-10-01T00:00:00.000Z');
    const existing = row({ disabledAt });
    vi.mocked(OidcClient.findByPk).mockResolvedValue(existing as never);

    await request(app).patch('/admin/applications/app-1').send({ disabled: true });
    expect(existing.update).toHaveBeenLastCalledWith(expect.objectContaining({ disabledAt }));

    const res = await request(app).patch('/admin/applications/app-1').send({ disabled: false });
    expect(res.body.application.disabled).toBe(false);

    existing.disabledAt = null;
    const again = await request(app).patch('/admin/applications/app-1').send({ disabled: true });
    expect(again.body.application.disabled).toBe(true);
  });

  it('refuses a client type change', async () => {
    const res = await request(app)
      .patch('/admin/applications/app-1')
      .send({ clientType: 'public' });

    expect(res.status).toBe(400);
  });

  it('answers 404 for an unknown application', async () => {
    vi.mocked(OidcClient.findByPk).mockResolvedValue(null);

    const res = await request(app).patch('/admin/applications/nope').send({ name: 'x' });

    expect(res.status).toBe(404);
  });
});

describe('PUT /admin/applications/:id/keys', () => {
  it('replaces a JWKS URI with an inline JWKS and audits the key ids', async () => {
    const existing = row();
    vi.mocked(OidcClient.findByPk).mockResolvedValue(existing as never);

    const res = await request(app)
      .put('/admin/applications/app-1/keys')
      .send({ jwks: { keys: [jwk] } });

    expect(res.status).toBe(200);
    expect(existing.update).toHaveBeenCalledWith({ jwks: { keys: [jwk] }, jwksUri: null });
    expect(vi.mocked(AuthEventService.log).mock.calls[0][0]).toMatchObject({
      type: 'admin_oidc_application_keys_updated',
      metadata: { clientId: 'app-1', source: 'jwks', kids: ['k1'] },
    });
  });

  it('replaces an inline JWKS with a JWKS URI', async () => {
    const existing = row({ jwks: { keys: [jwk] }, jwksUri: null });
    vi.mocked(OidcClient.findByPk).mockResolvedValue(existing as never);

    const res = await request(app)
      .put('/admin/applications/app-1/keys')
      .send({ jwksUri: 'https://grafana.example.com/keys' });

    expect(res.status).toBe(200);
    expect(existing.update).toHaveBeenCalledWith({
      jwks: null,
      jwksUri: 'https://grafana.example.com/keys',
    });
  });

  it('refuses keys for a client that does not use private_key_jwt', async () => {
    vi.mocked(OidcClient.findByPk).mockResolvedValue(
      row({ clientType: 'public', tokenEndpointAuthMethod: 'none' }) as never,
    );

    const res = await request(app)
      .put('/admin/applications/app-1/keys')
      .send({ jwks: { keys: [jwk] } });

    expect(res.status).toBe(400);
  });

  it('refuses a private key', async () => {
    const res = await request(app)
      .put('/admin/applications/app-1/keys')
      .send({ jwks: { keys: [{ ...jwk, d: 'secret' }] } });

    expect(res.status).toBe(400);
  });
});

describe('POST /admin/applications/:id/secret', () => {
  it('rotates the secret and stores only its HMAC', async () => {
    withConfig({ allow_client_secrets: true });
    const existing = row({
      tokenEndpointAuthMethod: 'client_secret_post',
      jwksUri: null,
      secretLookup: 'old',
    });
    vi.mocked(OidcClient.findByPk).mockResolvedValue(existing as never);

    const res = await request(app).post('/admin/applications/app-1/secret');

    expect(res.status).toBe(200);
    expect(existing.update).toHaveBeenCalledWith({
      secretLookup: createOidcClientSecretLookup(res.body.clientSecret),
    });
    expect(loggedTypes()).toEqual(['admin_oidc_application_secret_rotated']);
  });

  it('refuses a client that does not use a shared secret', async () => {
    withConfig({ allow_client_secrets: true });
    vi.mocked(OidcClient.findByPk).mockResolvedValue(row() as never);

    expect((await request(app).post('/admin/applications/app-1/secret')).status).toBe(400);
  });

  it('refuses while allow_client_secrets is off', async () => {
    vi.mocked(OidcClient.findByPk).mockResolvedValue(
      row({ tokenEndpointAuthMethod: 'client_secret_post', jwksUri: null }) as never,
    );

    const res = await request(app).post('/admin/applications/app-1/secret');

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/allow_client_secrets/);
  });
});

describe('DELETE /admin/applications/:id', () => {
  it('deletes the application, its resource grants and its provider records', async () => {
    const existing = row();
    vi.mocked(OidcClient.findByPk).mockResolvedValue(existing as never);

    const res = await request(app).delete('/admin/applications/app-1');

    expect(res.status).toBe(200);
    expect(OidcPayload.destroy).toHaveBeenCalledWith({
      where: { payload: { clientId: 'app-1' } },
      transaction: { tx: true },
    });
    expect(OidcClientResource.destroy).toHaveBeenCalledWith({
      where: { clientId: 'app-1' },
      transaction: { tx: true },
    });
    expect(existing.destroy).toHaveBeenCalledWith({ transaction: { tx: true } });
    expect(loggedTypes()).toEqual(['admin_oidc_application_deleted']);
  });

  it('answers 404 for an unknown application', async () => {
    vi.mocked(OidcClient.findByPk).mockResolvedValue(null);

    expect((await request(app).delete('/admin/applications/nope')).status).toBe(404);
    expect(loggedTypes()).toEqual([]);
  });
});
