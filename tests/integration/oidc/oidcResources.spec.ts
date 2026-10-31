import { Application } from 'express';
import { UniqueConstraintError } from 'sequelize';
import request from 'supertest';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/models/oidcClients.js', () => ({
  OidcClient: { findByPk: vi.fn() },
}));

vi.mock('../../../src/models/oidcResources.js', () => ({
  OidcResource: {
    findAll: vi.fn(),
    findByPk: vi.fn(),
    create: vi.fn(),
    sequelize: { transaction: vi.fn(async (fn: (tx: unknown) => unknown) => fn({ tx: true })) },
  },
}));

vi.mock('../../../src/models/oidcClientResources.js', () => ({
  OidcClientResource: {
    findAll: vi.fn(),
    destroy: vi.fn(),
    bulkCreate: vi.fn(),
    sequelize: { transaction: vi.fn(async (fn: (tx: unknown) => unknown) => fn({ tx: true })) },
  },
}));

vi.mock('../../../src/models/oidcPayloads.js', () => ({
  OidcPayload: { destroy: vi.fn() },
}));

import { createApp } from '../../../src/app';
import { getSystemConfig } from '../../../src/config/getSystemConfig';
import { OidcClientResource } from '../../../src/models/oidcClientResources.js';
import { OidcClient } from '../../../src/models/oidcClients.js';
import { OidcResource } from '../../../src/models/oidcResources.js';
import { Session } from '../../../src/models/sessions.js';
import { AuthEventService } from '../../../src/services/authEventService.js';
import { buildFreshStepUpSession } from '../../factories/sessionFactory';
import { buildSystemConfig } from '../../factories/systemConfigFactory';

const RESOURCE_ID = '0e1b4a52-9a43-4a8f-9e57-3f0b2d1f7c11';
const OTHER_ID = '7d0a5f0e-2c1b-4e57-9a43-3f0b2d1f7c22';
const ISSUER = 'https://login.example.com';

let app: Application;

function resource(overrides: Record<string, unknown> = {}) {
  const data: Record<string, unknown> = {
    id: RESOURCE_ID,
    identifier: 'https://api.example.com',
    name: 'Orders API',
    scopes: ['orders:read', 'orders:write'],
    accessTokenTtlSeconds: null,
    createdAt: new Date('2026-10-30T12:00:00.000Z'),
    updatedAt: new Date('2026-10-30T12:00:00.000Z'),
    ...overrides,
  };
  data.update = vi.fn(async (changes: Record<string, unknown>) => Object.assign(data, changes));
  data.destroy = vi.fn();
  return data as Record<string, unknown> & {
    update: ReturnType<typeof vi.fn>;
    destroy: ReturnType<typeof vi.fn>;
  };
}

function link(scopes: string[], resourceId = RESOURCE_ID) {
  return { clientId: 'app-1', resourceId, scopes, update: vi.fn() };
}

function loggedEvents() {
  return vi.mocked(AuthEventService.log).mock.calls.map(([event]) => ({
    type: event.type,
    metadata: event.metadata,
  }));
}

beforeAll(async () => {
  app = await createApp();
});

beforeEach(() => {
  vi.clearAllMocks();
  vi.unstubAllEnvs();
  vi.spyOn(AuthEventService, 'log').mockResolvedValue(undefined);
  (Session.findOne as ReturnType<typeof vi.fn>).mockResolvedValue(buildFreshStepUpSession());
  vi.mocked(getSystemConfig).mockResolvedValue(buildSystemConfig({ oidc_issuer: ISSUER }) as never);
  vi.mocked(OidcClient.findByPk).mockResolvedValue({ id: 'app-1' } as never);
  vi.mocked(OidcResource.create).mockImplementation(
    async (values: Record<string, unknown>) => resource(values) as never,
  );
});

describe('resources', () => {
  it('lists resources', async () => {
    vi.mocked(OidcResource.findAll).mockResolvedValue([resource()] as never);

    const res = await request(app).get('/admin/resources');

    expect(res.status).toBe(200);
    expect(res.body.resources).toEqual([
      expect.objectContaining({
        identifier: 'https://api.example.com',
        scopes: ['orders:read', 'orders:write'],
      }),
    ]);
  });

  it('gets one resource, or 404', async () => {
    vi.mocked(OidcResource.findByPk).mockResolvedValueOnce(resource() as never);
    expect((await request(app).get(`/admin/resources/${RESOURCE_ID}`)).status).toBe(200);

    vi.mocked(OidcResource.findByPk).mockResolvedValueOnce(null);
    const missing = await request(app).get(`/admin/resources/${RESOURCE_ID}`);
    expect(missing.status).toBe(404);
    expect(missing.body).toEqual({ error: 'Resource not found' });
  });

  it('creates a resource and audits it', async () => {
    const res = await request(app)
      .post('/admin/resources')
      .send({ identifier: 'https://api.example.com', name: 'Orders API', scopes: ['orders:read'] });

    expect(res.status).toBe(201);
    expect(res.body.resource).toMatchObject({
      scopes: ['orders:read'],
      accessTokenTtlSeconds: null,
    });
    expect(loggedEvents()[0]).toMatchObject({
      type: 'admin_oidc_resource_created',
      metadata: { identifier: 'https://api.example.com', scopes: ['orders:read'] },
    });
  });

  it.each([ISSUER, `${ISSUER}/`, 'http://localhost:3000', `${ISSUER}/seamless`])(
    'refuses an issuer as the identifier (%s)',
    async (identifier) => {
      vi.stubEnv('ISSUER', 'http://localhost:3000');

      const res = await request(app).post('/admin/resources').send({ identifier, name: 'Nope' });

      expect(res.status).toBe(400);
      expect(OidcResource.create).not.toHaveBeenCalled();
    },
  );

  it('answers 409 for a duplicate identifier', async () => {
    vi.mocked(OidcResource.create).mockRejectedValue(new UniqueConstraintError({}));

    const res = await request(app)
      .post('/admin/resources')
      .send({ identifier: 'https://api.example.com', name: 'Orders API' });

    expect(res.status).toBe(409);
  });

  it('passes on an unexpected failure', async () => {
    vi.mocked(OidcResource.create).mockRejectedValue(new Error('boom'));

    const res = await request(app)
      .post('/admin/resources')
      .send({ identifier: 'https://api.example.com', name: 'Orders API' });

    expect(res.status).toBe(500);
  });

  it('refuses a reserved scope', async () => {
    const res = await request(app)
      .post('/admin/resources')
      .send({ identifier: 'https://api.example.com', name: 'API', scopes: ['openid'] });

    expect(res.status).toBe(400);
  });

  it('removes a dropped scope from every application', async () => {
    const existing = resource();
    const narrowed = link(['orders:read', 'orders:write']);
    const untouched = link(['orders:read']);
    vi.mocked(OidcResource.findByPk).mockResolvedValue(existing as never);
    vi.mocked(OidcClientResource.findAll).mockResolvedValue([narrowed, untouched] as never);

    const res = await request(app)
      .patch(`/admin/resources/${RESOURCE_ID}`)
      .send({ scopes: ['orders:read'] });

    expect(res.status).toBe(200);
    expect(narrowed.update).toHaveBeenCalledWith(
      { scopes: ['orders:read'] },
      { transaction: { tx: true } },
    );
    expect(untouched.update).not.toHaveBeenCalled();
    expect(loggedEvents()[0]).toMatchObject({
      type: 'admin_oidc_resource_updated',
      metadata: { changed: ['scopes'], scopes: ['orders:read'] },
    });
  });

  it('renames without touching applications', async () => {
    vi.mocked(OidcResource.findByPk).mockResolvedValue(resource() as never);

    const res = await request(app)
      .patch(`/admin/resources/${RESOURCE_ID}`)
      .send({ name: 'Renamed' });

    expect(res.status).toBe(200);
    expect(res.body.resource.name).toBe('Renamed');
    expect(OidcClientResource.findAll).not.toHaveBeenCalled();
  });

  it('cannot change the identifier', async () => {
    const res = await request(app)
      .patch(`/admin/resources/${RESOURCE_ID}`)
      .send({ identifier: 'https://other.example.com' });

    expect(res.status).toBe(400);
  });

  it('deletes a resource and its application grants', async () => {
    const existing = resource();
    vi.mocked(OidcResource.findByPk).mockResolvedValue(existing as never);

    const res = await request(app).delete(`/admin/resources/${RESOURCE_ID}`);

    expect(res.status).toBe(200);
    expect(OidcClientResource.destroy).toHaveBeenCalledWith({
      where: { resourceId: RESOURCE_ID },
      transaction: { tx: true },
    });
    expect(existing.destroy).toHaveBeenCalled();
    expect(loggedEvents()[0].type).toBe('admin_oidc_resource_deleted');
  });

  it('answers 404 when deleting an unknown resource', async () => {
    vi.mocked(OidcResource.findByPk).mockResolvedValue(null);

    expect((await request(app).delete(`/admin/resources/${RESOURCE_ID}`)).status).toBe(404);
  });
});

describe('application resources', () => {
  it('lists what an application may use, never more than the resource declares', async () => {
    vi.mocked(OidcClientResource.findAll).mockResolvedValue([
      link(['orders:read', 'orders:delete']),
    ] as never);
    vi.mocked(OidcResource.findAll).mockResolvedValue([resource()] as never);

    const res = await request(app).get('/admin/applications/app-1/resources');

    expect(res.status).toBe(200);
    expect(res.body.resources).toEqual([
      {
        resourceId: RESOURCE_ID,
        identifier: 'https://api.example.com',
        name: 'Orders API',
        scopes: ['orders:read'],
      },
    ]);
  });

  it('lists nothing for an application with no resources', async () => {
    vi.mocked(OidcClientResource.findAll).mockResolvedValue([]);

    const res = await request(app).get('/admin/applications/app-1/resources');

    expect(res.body.resources).toEqual([]);
    expect(OidcResource.findAll).not.toHaveBeenCalled();
  });

  it('answers 404 for an unknown application', async () => {
    vi.mocked(OidcClient.findByPk).mockResolvedValue(null);

    expect((await request(app).get('/admin/applications/nope/resources')).status).toBe(404);
    expect(
      (await request(app).put('/admin/applications/nope/resources').send({ resources: [] })).status,
    ).toBe(404);
  });

  it('replaces the set and audits it', async () => {
    vi.mocked(OidcResource.findAll).mockResolvedValue([resource()] as never);
    vi.mocked(OidcClientResource.findAll).mockResolvedValue([link(['orders:read'])] as never);

    const res = await request(app)
      .put('/admin/applications/app-1/resources')
      .send({ resources: [{ resourceId: RESOURCE_ID, scopes: ['orders:read'] }] });

    expect(res.status).toBe(200);
    expect(OidcClientResource.destroy).toHaveBeenCalledWith({
      where: { clientId: 'app-1' },
      transaction: { tx: true },
    });
    expect(OidcClientResource.bulkCreate).toHaveBeenCalledWith(
      [{ clientId: 'app-1', resourceId: RESOURCE_ID, scopes: ['orders:read'] }],
      { transaction: { tx: true } },
    );
    expect(loggedEvents()[0]).toEqual({
      type: 'admin_oidc_application_resources_updated',
      metadata: {
        clientId: 'app-1',
        resources: [{ identifier: 'https://api.example.com', scopes: ['orders:read'] }],
      },
    });
  });

  it('clears the set', async () => {
    vi.mocked(OidcClientResource.findAll).mockResolvedValue([]);

    const res = await request(app)
      .put('/admin/applications/app-1/resources')
      .send({ resources: [] });

    expect(res.status).toBe(200);
    expect(OidcClientResource.destroy).toHaveBeenCalled();
    expect(OidcClientResource.bulkCreate).not.toHaveBeenCalled();
  });

  it('refuses a scope the resource does not declare', async () => {
    vi.mocked(OidcResource.findAll).mockResolvedValue([resource()] as never);

    const res = await request(app)
      .put('/admin/applications/app-1/resources')
      .send({ resources: [{ resourceId: RESOURCE_ID, scopes: ['orders:delete'] }] });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('https://api.example.com does not declare orders:delete');
    expect(OidcClientResource.destroy).not.toHaveBeenCalled();
  });

  it('refuses an unknown resource', async () => {
    vi.mocked(OidcResource.findAll).mockResolvedValue([resource()] as never);

    const res = await request(app)
      .put('/admin/applications/app-1/resources')
      .send({ resources: [{ resourceId: OTHER_ID, scopes: [] }] });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe(`Unknown resource ${OTHER_ID}`);
  });
});
