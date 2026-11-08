import { generateKeyPairSync, randomUUID } from 'crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { invalidateSystemConfigCache } from '../../src/config/getSystemConfig.js';
import { getSequelize, initializeModels } from '../../src/models/index.js';
import { buildSystemConfig } from '../factories/systemConfigFactory.js';

const PROVIDER_ISSUER = 'https://login.provider-claims.test';
const RESOURCE = 'https://orders.provider-claims.test';
const KID = 'provider-claims-key';
const role = `pc-role-${randomUUID().slice(0, 8)}`;
const orgRole = `pc-org-${randomUUID().slice(0, 8)}`;
const permission = `pc:${randomUUID().slice(0, 8)}`;

const providerKey = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey;
const savedEnv: Record<string, string | undefined> = {};

type Models = Awaited<ReturnType<typeof initializeModels>>;
type Signing = typeof import('../../src/services/oidcSigning.js');
type AccountClaims = typeof import('../../src/services/oidcAccountClaims.js');
type Store = typeof import('../../src/services/oidcPayloadStore.js');
type Claims = typeof import('../../src/services/customClaimService.js');
type Permissions = typeof import('../../src/services/permissionService.js');

let models: Models;
let signing: Signing;
let accountClaims: AccountClaims;
let store: Store;
let claims: Claims;
let permissions: Permissions;

async function setConfig(key: string, value: unknown) {
  await getSequelize().query(
    `INSERT INTO system_config (key, value, "createdAt", "updatedAt")
     VALUES (:key, CAST(:value AS jsonb), now(), now())
     ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
    { replacements: { key, value: JSON.stringify(value) } },
  );
}

beforeAll(async () => {
  for (const [key, value] of Object.entries({
    OIDC_JWKS_ACTIVE_KID: KID,
    OIDC_JWKS_KEYS: JSON.stringify({
      keys: [{ ...providerKey.export({ format: 'jwk' }), kid: KID }],
    }),
  })) {
    savedEnv[key] = process.env[key];
    process.env[key] = value;
  }

  models = await initializeModels();
  for (const [key, value] of Object.entries(
    buildSystemConfig({ available_roles: ['user', role] }),
  )) {
    await setConfig(key, value);
  }
  await setConfig('oidc_issuer', PROVIDER_ISSUER);
  invalidateSystemConfigCache();

  signing = await import('../../src/services/oidcSigning.js');
  accountClaims = await import('../../src/services/oidcAccountClaims.js');
  store = await import('../../src/services/oidcPayloadStore.js');
  claims = await import('../../src/services/customClaimService.js');
  permissions = await import('../../src/services/permissionService.js');

  await permissions.createPermission(permission);
  await permissions.setRolePermissions({
    kind: 'instance',
    name: role,
    permissions: [permission],
    actorUserId: null,
  });
  await permissions.createOrganizationRole({
    name: orgRole,
    permissions: [permission],
    actorUserId: null,
  });
});

afterAll(async () => {
  await getSequelize().query('DELETE FROM custom_claims;');
  await setConfig('available_roles', ['user']);
  await getSequelize().query(`DELETE FROM system_config WHERE key = 'oidc_issuer'`);
  invalidateSystemConfigCache();
  for (const [key, value] of Object.entries(savedEnv)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  await getSequelize().close();
});

/** A member signed in through the provider for a client that has its own custom claims. */
async function providerMember() {
  const { OidcClient, OidcClientResource, OidcResource, Organization, OrganizationMembership } =
    models;
  const userId = randomUUID();
  const user = await models.User.create({
    id: userId,
    email: `${userId}@provider-claims.test`,
    phone: null,
    roles: [role],
  });
  const organization = await Organization.create({
    name: `Acme ${userId.slice(0, 8)}`,
    slug: `acme-${userId.slice(0, 8)}`,
  });
  await OrganizationMembership.create({
    organizationId: organization.id,
    userId,
    roles: [orgRole],
  });
  const client = await OidcClient.create({
    id: `pc-${randomUUID()}`,
    name: 'Orders',
    firstParty: true,
    clientType: 'public',
    tokenEndpointAuthMethod: 'none',
    redirectUris: ['https://app.provider-claims.test/cb'],
    grantTypes: ['authorization_code', 'refresh_token'],
  });
  const resource = await OidcResource.findOne({ where: { identifier: RESOURCE } });
  const linked =
    resource ??
    (await OidcResource.create({
      identifier: RESOURCE,
      name: 'Orders',
      scopes: ['read'],
    } as never));
  await OidcClientResource.create({
    clientId: client.id,
    resourceId: linked.id,
    scopes: ['read'],
  } as never);

  const now = Date.now();
  const session = await models.Session.create({
    userId,
    organizationId: organization.id,
    mode: 'server',
    refreshTokenLookup: randomUUID().replaceAll('-', ''),
    expiresAt: new Date(now + 3_600_000),
    idleExpiresAt: new Date(now + 3_600_000),
    lastUsedAt: new Date(now),
    chainStartedAt: new Date(now),
    hookClaims: { seats: 10 },
  });
  await store.bindOidcSession(session.id, userId, client.id);
  await store.upsertOidcPayload('Grant', randomUUID(), {
    payload: { accountId: userId, clientId: client.id },
    expiresIn: 3600,
    sessionId: session.id,
  });

  await claims.setCustomClaimSource('instance_role', role, { plan: 'free', region: 'us' });
  await claims.setCustomClaimSource('organization_role', orgRole, { plan: 'team' });
  await claims.setCustomClaimSource('oidc_client', client.id, {
    plan: 'client',
    tenant: { name: 'acme', tier: 2 },
  });

  return { user, organization, client, session };
}

function signingInput(header: Record<string, unknown>, body: Record<string, unknown>) {
  const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${encode(header)}.${encode(body)}`;
}

function sign(
  kind: 'id_token' | 'access_token',
  member: Awaited<ReturnType<typeof providerMember>>,
  extra: Record<string, unknown>,
) {
  const now = Math.floor(Date.now() / 1000);
  const base =
    kind === 'id_token'
      ? { aud: member.client.id }
      : { aud: RESOURCE, client_id: member.client.id, scope: 'read' };
  return signing.signForOidcEdge({
    kind,
    kid: KID,
    clientId: member.client.id,
    sessionId: member.session.id,
    grantType: 'authorization_code',
    signingInput: signingInput(
      { alg: 'RS256', kid: KID, ...(kind === 'access_token' ? { typ: 'at+jwt' } : {}) },
      JSON.parse(
        JSON.stringify({
          iss: PROVIDER_ISSUER,
          sub: member.user.id,
          exp: now + 300,
          iat: now,
          ...base,
          ...extra,
        }),
      ),
    ),
  });
}

describe('provider token claims on the deployed schema', () => {
  it('computes permissions, the active organization and every custom claim source in order', async () => {
    const member = await providerMember();

    const account = await accountClaims.getOidcAccountClaims(member.session, member.client.id);

    expect(account).toMatchObject({
      sub: member.user.id,
      roles: [role],
      org_id: member.organization.id,
      permissions: [permission],
      org_roles: [orgRole],
      org_permissions: [permission],
      // Instance role, organization role, client, then hook.
      customClaims: { plan: 'client', region: 'us', tenant: { name: 'acme', tier: 2 }, seats: 10 },
    });
  });

  it('signs those values into ID and access tokens, and refuses forged or unlisted ones', async () => {
    const member = await providerMember();
    const account = await accountClaims.getOidcAccountClaims(member.session, member.client.id);
    const carried = accountClaims.providerTokenClaims(account!);
    delete carried.sub;
    delete carried.email;
    delete carried.email_verified;

    expect((await sign('id_token', member, carried)).ok).toBe(true);
    expect((await sign('access_token', member, carried)).ok).toBe(true);

    expect(await sign('id_token', member, { ...carried, plan: 'enterprise' })).toMatchObject({
      code: 'subject_mismatch',
    });
    expect(
      await sign('access_token', member, { ...carried, permissions: [permission, 'admin:write'] }),
    ).toMatchObject({ code: 'subject_mismatch' });
    expect(await sign('id_token', member, { ...carried, is_admin: true })).toMatchObject({
      code: 'malformed_signing_input',
    });
    expect(await sign('id_token', member, { ...carried, act: { sub: 'x' } })).toMatchObject({
      code: 'malformed_signing_input',
    });
  });

  it('stops signing a client set that was removed, and org claims once the member leaves', async () => {
    const member = await providerMember();
    const before = accountClaims.providerTokenClaims(
      (await accountClaims.getOidcAccountClaims(member.session, member.client.id))!,
    );

    await claims.deleteCustomClaimSource('oidc_client', member.client.id);
    expect(await sign('access_token', member, { tenant: before.tenant })).toMatchObject({
      code: 'malformed_signing_input',
    });

    await models.OrganizationMembership.destroy({ where: { userId: member.user.id } });
    expect(
      await sign('access_token', member, {
        org_id: before.org_id,
        permissions: before.permissions,
        org_roles: before.org_roles,
        org_permissions: before.org_permissions,
      }),
    ).toMatchObject({ code: 'subject_mismatch' });

    const after = await accountClaims.getOidcAccountClaims(member.session, member.client.id);
    expect(after).toMatchObject({ org_id: null, customClaims: { plan: 'free', region: 'us' } });
    expect(after).not.toHaveProperty('org_roles');
    // The hook's claims were decided for that organization.
    expect(after?.customClaims).not.toHaveProperty('seats');
  });
});
