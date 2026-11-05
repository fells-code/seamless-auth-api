import { Application } from 'express';
import request from 'supertest';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/models/oidcClients.js', () => ({
  OidcClient: { findAll: vi.fn(), findByPk: vi.fn() },
}));

import { createApp } from '../../../src/app';
import { getSystemConfig } from '../../../src/config/getSystemConfig';
import { OidcClientLink } from '../../../src/models/oidcClientLinks.js';
import { OidcClient } from '../../../src/models/oidcClients.js';
import { Session } from '../../../src/models/sessions.js';
import { AuthEventService } from '../../../src/services/authEventService.js';
import { buildFreshStepUpSession } from '../../factories/sessionFactory';
import { buildSystemConfig } from '../../factories/systemConfigFactory';

const CREATED = new Date('2026-11-02T12:00:00.000Z');

let app: Application;

function client(id: string, overrides: Record<string, unknown> = {}) {
  return {
    id,
    name: id,
    clientType: 'public',
    firstParty: true,
    tokenEndpointAuthMethod: 'none',
    jwks: null,
    jwksUri: null,
    secretLookup: null,
    redirectUris: ['http://127.0.0.1/callback'],
    postLogoutRedirectUris: [],
    grantTypes: ['authorization_code', 'refresh_token'],
    backchannelLogoutUri: null,
    accessTokenTtlSeconds: null,
    idTokenTtlSeconds: null,
    refreshTokenTtlSeconds: null,
    deviceFlowEnabled: false,
    noticesEnabled: false,
    sessionExchangeEnabled: false,
    noticeActionOrigins: [],
    pkceRequired: true,
    nonceRequired: true,
    disabledAt: null,
    createdAt: CREATED,
    updatedAt: CREATED,
    ...overrides,
  };
}

const backend = (overrides: Record<string, unknown> = {}) =>
  client('registry', {
    clientType: 'confidential',
    tokenEndpointAuthMethod: 'private_key_jwt',
    redirectUris: [],
    grantTypes: ['client_credentials'],
    ...overrides,
  });

function registry(...clients: ReturnType<typeof client>[]) {
  const byId = new Map(clients.map((c) => [c.id, c]));
  vi.mocked(OidcClient.findByPk).mockImplementation(
    async (id: unknown) => (byId.get(id as string) ?? null) as never,
  );
}

function link(clientId: string, linkedClientId: string) {
  return { clientId, linkedClientId, createdBy: 'admin-1', createdAt: CREATED };
}

function loggedEvents() {
  return vi.mocked(AuthEventService.log).mock.calls.map(([event]) => ({
    type: event.type,
    metadata: event.metadata,
  }));
}

function withConfig(overrides: Record<string, unknown> = {}) {
  vi.mocked(getSystemConfig).mockResolvedValue(
    buildSystemConfig({ third_party_clients_enabled: false, ...overrides }) as never,
  );
}

beforeAll(async () => {
  app = await createApp();
});

beforeEach(() => {
  vi.clearAllMocks();
  vi.spyOn(AuthEventService, 'log').mockResolvedValue(undefined);
  (Session.findOne as ReturnType<typeof vi.fn>).mockResolvedValue(buildFreshStepUpSession());
  vi.mocked(OidcClientLink.findAll).mockResolvedValue([]);
  vi.mocked(OidcClientLink.findOrCreate).mockImplementation(
    async ({ defaults }: { defaults?: Record<string, unknown> }) =>
      [{ ...defaults, createdAt: CREATED }, true] as never,
  );
  withConfig();
  registry(backend(), client('desktop'));
});

describe('GET /admin/applications/:id/links', () => {
  it('lists the links in both directions', async () => {
    vi.mocked(OidcClientLink.findAll).mockImplementation(async (options) => {
      const where = (options as { where: Record<string, string> }).where;
      return (where.clientId ? [link('registry', 'desktop')] : []) as never;
    });

    const res = await request(app).get('/admin/applications/registry/links');

    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      links: [
        {
          clientId: 'registry',
          linkedClientId: 'desktop',
          createdBy: 'admin-1',
          createdAt: CREATED.toISOString(),
        },
      ],
      linkedFrom: [],
    });
  });

  it('answers 404 for an unknown application', async () => {
    const res = await request(app).get('/admin/applications/nope/links');

    expect(res.status).toBe(404);
    expect(OidcClientLink.findAll).not.toHaveBeenCalled();
  });
});

describe('application responses', () => {
  it('list the clients an application acts for and the ones acting for it', async () => {
    vi.mocked(OidcClient.findAll).mockResolvedValue([backend(), client('desktop')] as never);
    vi.mocked(OidcClientLink.findAll).mockResolvedValue([link('registry', 'desktop')] as never);

    const res = await request(app).get('/admin/applications');

    expect(res.status).toBe(200);
    expect(res.body.applications).toEqual([
      expect.objectContaining({
        id: 'registry',
        links: ['desktop'],
        linkedFrom: [],
        noticeActionOrigins: [],
      }),
      expect.objectContaining({ id: 'desktop', links: [], linkedFrom: ['registry'] }),
    ]);
  });
});

describe('PUT /admin/applications/:id/links/:linkedId', () => {
  it('links a confidential backend to a public client of the same party, and audits it', async () => {
    const res = await request(app).put('/admin/applications/registry/links/desktop');

    expect(res.status).toBe(200);
    expect(res.body.link).toMatchObject({ clientId: 'registry', linkedClientId: 'desktop' });
    expect(OidcClientLink.findOrCreate).toHaveBeenCalledWith({
      where: { clientId: 'registry', linkedClientId: 'desktop' },
      defaults: { clientId: 'registry', linkedClientId: 'desktop', createdBy: 'user-1' },
    });
    expect(loggedEvents()).toEqual([
      {
        type: 'admin_oidc_application_link_added',
        metadata: { clientId: 'registry', linkedClientId: 'desktop' },
      },
    ]);
  });

  it('does not audit a link that already existed', async () => {
    vi.mocked(OidcClientLink.findOrCreate).mockResolvedValue([
      link('registry', 'desktop'),
      false,
    ] as never);

    const res = await request(app).put('/admin/applications/registry/links/desktop');

    expect(res.status).toBe(200);
    expect(loggedEvents()).toEqual([]);
  });

  it.each([
    [
      'a public client acting',
      () => registry(client('registry'), client('desktop')),
      'Only a confidential application can act for another',
    ],
    [
      'a confidential client acted for',
      () => registry(backend(), backend({ id: 'desktop' })),
      'Only a public application can be acted for; a confidential one sends its own notices',
    ],
    [
      'a first-party backend reaching a third-party client',
      () => registry(backend(), client('desktop', { firstParty: false })),
      'Links stay within first-party or within third-party applications',
    ],
    [
      'a third-party backend reaching a first-party client',
      () => {
        withConfig({ third_party_clients_enabled: true });
        registry(backend({ firstParty: false }), client('desktop'));
      },
      'Links stay within first-party or within third-party applications',
    ],
    [
      'third-party clients while they are off',
      () => registry(backend({ firstParty: false }), client('desktop', { firstParty: false })),
      'Third-party clients are off on this instance (third_party_clients_enabled)',
    ],
  ])('refuses %s', async (_label, arrange, error) => {
    arrange();

    const res = await request(app).put('/admin/applications/registry/links/desktop');

    expect(res.status).toBe(400);
    expect(res.body).toEqual({ error });
    expect(OidcClientLink.findOrCreate).not.toHaveBeenCalled();
    expect(loggedEvents()).toEqual([]);
  });

  it('refuses a link to itself', async () => {
    const res = await request(app).put('/admin/applications/registry/links/registry');

    expect(res.status).toBe(400);
    expect(res.body).toEqual({ error: 'An application cannot be linked to itself' });
  });

  it('links third-party clients once third-party clients are on', async () => {
    withConfig({ third_party_clients_enabled: true });
    registry(backend({ firstParty: false }), client('desktop', { firstParty: false }));

    const res = await request(app).put('/admin/applications/registry/links/desktop');

    expect(res.status).toBe(200);
  });

  it.each(['/admin/applications/nope/links/desktop', '/admin/applications/registry/links/nope'])(
    'answers 404 for an unknown application (%s)',
    async (path) => {
      const res = await request(app).put(path);

      expect(res.status).toBe(404);
      expect(OidcClientLink.findOrCreate).not.toHaveBeenCalled();
    },
  );
});

describe('DELETE /admin/applications/:id/links/:linkedId', () => {
  it('removes the link and audits it', async () => {
    vi.mocked(OidcClientLink.destroy).mockResolvedValue(1);

    const res = await request(app).delete('/admin/applications/registry/links/desktop');

    expect(res.status).toBe(200);
    expect(OidcClientLink.destroy).toHaveBeenCalledWith({
      where: { clientId: 'registry', linkedClientId: 'desktop' },
    });
    expect(loggedEvents()).toEqual([
      {
        type: 'admin_oidc_application_link_removed',
        metadata: { clientId: 'registry', linkedClientId: 'desktop' },
      },
    ]);
  });

  it('answers 404 when there is no such link', async () => {
    vi.mocked(OidcClientLink.destroy).mockResolvedValue(0);

    const res = await request(app).delete('/admin/applications/registry/links/desktop');

    expect(res.status).toBe(404);
    expect(res.body).toEqual({ error: 'Link not found' });
    expect(loggedEvents()).toEqual([]);
  });
});
