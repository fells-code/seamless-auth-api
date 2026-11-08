import { randomUUID } from 'crypto';
import { decodeJwt } from 'jose';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import { invalidateSystemConfigCache } from '../../src/config/getSystemConfig.js';
import { AuthEvent } from '../../src/models/authEvents.js';
import { CustomClaim } from '../../src/models/customClaims.js';
import { getSequelize, initializeModels } from '../../src/models/index.js';
import { OidcClient } from '../../src/models/oidcClients.js';
import { mintAccessToken } from '../../src/services/accessTokenService.js';
import { setCustomClaimSource } from '../../src/services/customClaimService.js';
import { deleteOidcApplication } from '../../src/services/oidcApplicationService.js';
import {
  createOrganizationRole,
  deleteRoleMappings,
} from '../../src/services/permissionService.js';
import { buildSystemConfig } from '../factories/systemConfigFactory.js';

vi.hoisted(() => {
  process.env.ISSUER = 'http://localhost:5312';
});

type Models = Awaited<ReturnType<typeof initializeModels>>;
let models: Models;

const role = 'claims-role';

async function setAvailableRoles(roles: string[]) {
  for (const [key, value] of Object.entries(buildSystemConfig({ available_roles: roles }))) {
    await getSequelize().query(
      `INSERT INTO system_config (key, value, "createdAt", "updatedAt")
       VALUES (:key, CAST(:value AS jsonb), now(), now())
       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
      { replacements: { key, value: JSON.stringify(value) } },
    );
  }
  invalidateSystemConfigCache();
}

beforeAll(async () => {
  models = await initializeModels();
});

beforeEach(async () => {
  await getSequelize().query('DELETE FROM custom_claims;');
  await setAvailableRoles(['user', role]);
});

afterAll(async () => {
  await getSequelize().query('DELETE FROM custom_claims;');
  await setAvailableRoles(['user']);
  await getSequelize().close();
});

async function member(orgRoles: string[]) {
  const { Organization, OrganizationMembership, Session, User } = models;
  const userId = randomUUID();
  const user = await User.create({
    id: userId,
    email: `${userId}@example.com`,
    phone: null,
    roles: [role],
  });
  const organization = await Organization.create({
    name: `Acme ${userId.slice(0, 8)}`,
    slug: `acme-${userId.slice(0, 8)}`,
  });
  const membership = await OrganizationMembership.create({
    organizationId: organization.id,
    userId,
    roles: orgRoles,
  });
  const now = Date.now();
  const session = await Session.create({
    userId,
    organizationId: organization.id,
    mode: 'server',
    refreshTokenLookup: randomUUID(),
    expiresAt: new Date(now + 3_600_000),
    idleExpiresAt: new Date(now + 3_600_000),
    hookClaims: { seats: 10 },
  });
  return { user, organization, membership, session };
}

describe('custom claims on the deployed schema', () => {
  it('merge instance, organization and hook claims into the token, until the member leaves', async () => {
    const orgRole = `claims-org-${randomUUID().slice(0, 8)}`;
    await createOrganizationRole({ name: orgRole, actorUserId: null });
    await setCustomClaimSource('instance_role', role, { plan: 'free', region: 'us' });
    await setCustomClaimSource('organization_role', orgRole, { plan: 'team', seats: 5 });
    const { user, membership, session } = await member([orgRole]);

    const before = decodeJwt((await mintAccessToken({ session, user })).token);
    expect(before).toMatchObject({ plan: 'team', region: 'us', seats: 10 });

    await membership.destroy();
    const after = decodeJwt((await mintAccessToken({ session, user })).token);
    expect(after).toMatchObject({ plan: 'free', region: 'us' });
    expect(after).not.toHaveProperty('seats');
  });

  it('omits them all, and records it, when the sources together exceed the budget', async () => {
    await setCustomClaimSource('instance_role', role, { a: 'x'.repeat(1000) });
    const { user, session } = await member([]);
    await session.update({ hookClaims: { b: 'y'.repeat(100) } });

    const claims = decodeJwt((await mintAccessToken({ session, user })).token);

    expect(claims).not.toHaveProperty('a');
    expect(claims).not.toHaveProperty('b');
    const event = await AuthEvent.findOne({
      where: { type: 'custom_claims_omitted', session_id: session.id },
    });
    expect(event?.metadata).toMatchObject({ budgetBytes: 1024 });
  });

  it('are deleted with a role or client leaving the instance, so the name cannot get them back', async () => {
    const clientId = `claims-${randomUUID()}`;
    await OidcClient.create({
      id: clientId,
      name: clientId,
      firstParty: true,
      clientType: 'public',
      tokenEndpointAuthMethod: 'none',
      redirectUris: ['http://127.0.0.1/cb'],
    });
    await setCustomClaimSource('instance_role', role, { plan: 'pro' });
    await setCustomClaimSource('oidc_client', clientId, { tenant: 'acme' });

    await deleteRoleMappings('instance', [role]);
    await deleteOidcApplication(clientId);

    expect(await CustomClaim.count()).toBe(0);
  });

  it('refuses a source kind the table does not know', async () => {
    await expect(
      getSequelize().query(
        `INSERT INTO custom_claims ("sourceKind", "sourceName", claims, "createdAt", "updatedAt")
         VALUES ('session', 'x', '{}', now(), now())`,
      ),
    ).rejects.toThrow(/custom_claims_source_kind/);
  });
});
