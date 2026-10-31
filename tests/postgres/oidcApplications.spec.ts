import { randomUUID } from 'crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { getSequelize, initializeModels } from '../../src/models/index.js';
import { OidcClientResource } from '../../src/models/oidcClientResources.js';
import { OidcClient } from '../../src/models/oidcClients.js';
import { OidcPayload } from '../../src/models/oidcPayloads.js';
import { OidcResource } from '../../src/models/oidcResources.js';
import { deleteOidcApplication } from '../../src/services/oidcApplicationService.js';
import { getOidcClientResourceScopes } from '../../src/services/oidcClientRegistry.js';
import { upsertOidcPayload } from '../../src/services/oidcPayloadStore.js';
import {
  createOidcResource,
  deleteOidcResource,
  setOidcApplicationResources,
  updateOidcResource,
} from '../../src/services/oidcResourceService.js';

beforeAll(async () => {
  await initializeModels();
});

afterAll(async () => {
  await getSequelize().close();
});

async function createClient(id: string) {
  return OidcClient.create({
    id,
    name: id,
    clientType: 'public',
    tokenEndpointAuthMethod: 'none',
    redirectUris: ['http://127.0.0.1/cb'],
  });
}

describe('deleting an application', () => {
  it('removes its resource grants and provider records, and no other client', async () => {
    const id = `app-${randomUUID()}`;
    const other = `app-${randomUUID()}`;
    await createClient(id);
    await createClient(other);

    const resource = await OidcResource.create({
      identifier: `https://api-${randomUUID()}.example.com`,
      name: 'API',
      scopes: ['read'],
    });
    await OidcClientResource.create({ clientId: id, resourceId: resource.id, scopes: ['read'] });

    const mine = randomUUID();
    const theirs = randomUUID();
    await upsertOidcPayload('Grant', mine, { payload: { clientId: id }, expiresIn: 600 });
    await upsertOidcPayload('Grant', theirs, { payload: { clientId: other }, expiresIn: 600 });

    await deleteOidcApplication(id);

    expect(await OidcClient.findByPk(id)).toBeNull();
    expect(await OidcClient.findByPk(other)).not.toBeNull();
    expect(await OidcClientResource.count({ where: { clientId: id } })).toBe(0);
    expect(await OidcResource.findByPk(resource.id)).not.toBeNull();
    expect(await OidcPayload.findOne({ where: { model: 'Grant', id: mine } })).toBeNull();
    expect(await OidcPayload.findOne({ where: { model: 'Grant', id: theirs } })).not.toBeNull();
  });
});

describe('application resources', () => {
  it('feed the audiences and scopes the provider may sign for', async () => {
    const id = `app-${randomUUID()}`;
    await createClient(id);
    const identifier = `https://api-${randomUUID()}.example.com`;
    const resource = await createOidcResource({
      identifier,
      name: 'Orders',
      scopes: ['orders:read', 'orders:write'],
    });

    await setOidcApplicationResources(id, {
      resources: [{ resourceId: resource.id, scopes: ['orders:read', 'orders:write'] }],
    });
    expect((await getOidcClientResourceScopes(id)).get(identifier)).toEqual(
      new Set(['orders:read', 'orders:write']),
    );

    await updateOidcResource(resource.id, { scopes: ['orders:read'] });
    const link = await OidcClientResource.findOne({ where: { clientId: id } });
    expect(link?.scopes).toEqual(['orders:read']);

    await deleteOidcResource(resource.id);
    expect((await getOidcClientResourceScopes(id)).size).toBe(0);
  });
});
