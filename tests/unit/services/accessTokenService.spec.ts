import { generateKeyPairSync } from 'crypto';
import { SignJWT, decodeJwt } from 'jose';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.unmock('../../../src/lib/token');

vi.hoisted(() => {
  process.env.ISSUER = 'https://auth.customer-domain.example.com';
});

vi.mock('../../../src/utils/signingKeyStore.js', () => ({
  getSigningKey: vi.fn(),
}));

import { CUSTOM_CLAIMS_BUDGET_BYTES, customClaimsByteLength } from '@seamless-auth/types';

import { getSystemConfig } from '../../../src/config/getSystemConfig.js';
import { CustomClaim } from '../../../src/models/customClaims.js';
import { AuthEventService } from '../../../src/services/authEventService.js';
import { signAccessToken } from '../../../src/lib/token.js';
import { OrganizationMembership } from '../../../src/models/organizationMemberships.js';
import { RolePermission } from '../../../src/models/rolePermissions.js';
import { Session } from '../../../src/models/sessions.js';
import {
  authorizationClaims,
  mintAccessToken,
  PERMISSION_CLAIMS_BUDGET_BYTES,
  resolveAuthorization,
} from '../../../src/services/accessTokenService.js';
import { getSigningKey } from '../../../src/utils/signingKeyStore.js';

const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();

function mappings(...names: string[]) {
  (RolePermission.findAll as any).mockResolvedValue(
    names.map((permissionName) => ({ permissionName })),
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  (getSigningKey as any).mockResolvedValue({ kid: 'k1', privateKeyPem });
  (getSystemConfig as any).mockResolvedValue({ access_token_ttl: '15m' });
  mappings();
  (OrganizationMembership.findOne as any).mockResolvedValue(undefined);
});

const user = { id: '7b6f7a0e-52a4-4f1b-9d32-4c1a0f1e2d3c', roles: ['user'] };
const session = { id: '0f4a9a3e-1d7c-4b9e-8a11-2f6c7d8e9a0b' };

function fittingPermissions() {
  const permissions: string[] = [];

  for (let index = 0; ; index += 1) {
    const next = [...permissions, `resource-${index}:action`];

    if (Buffer.byteLength(JSON.stringify({ permissions: next })) > PERMISSION_CLAIMS_BUDGET_BYTES) {
      return permissions;
    }

    permissions.push(next[next.length - 1]);
  }
}

const organizationId = '2c0d53c2-a541-452b-b71b-54c7f15e5877';
const noOrganization = { organizationId: null, organizationRoles: [], organizationPermissions: [] };

function mappingsByKind(instance: string[], organization: string[]) {
  (RolePermission.findAll as any).mockImplementation(async ({ where }: any) =>
    (where.roleKind === 'organization' ? organization : instance).map((permissionName) => ({
      permissionName,
    })),
  );
}

function memberOf(roles: unknown) {
  (OrganizationMembership.findOne as any).mockResolvedValue({ roles });
}

describe('resolveAuthorization', () => {
  const base = { userId: user.id, recovery: false };

  it('reads what the roles grant, deduplicated and sorted', async () => {
    mappings('b:read', 'a:read', 'b:read');

    await expect(resolveAuthorization({ ...base, roles: ['x', 'y'] })).resolves.toEqual({
      roles: ['x', 'y'],
      permissions: ['a:read', 'b:read'],
      ...noOrganization,
    });
    expect(RolePermission.findAll).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({ roleKind: 'instance' }),
      }),
    );
  });

  it('keeps instance and organization grants apart', async () => {
    mappingsByKind(['reports:read'], ['projects:write']);
    memberOf(['admin']);

    await expect(
      resolveAuthorization({ ...base, roles: ['user'], organizationId }),
    ).resolves.toEqual({
      roles: ['user'],
      permissions: ['reports:read'],
      organizationId,
      organizationRoles: ['admin'],
      organizationPermissions: ['projects:write'],
    });
  });

  it('holds nothing in an organization the user no longer belongs to', async () => {
    mappingsByKind(['reports:read'], ['projects:write']);
    (OrganizationMembership.findOne as any).mockResolvedValue(null);

    await expect(
      resolveAuthorization({ ...base, roles: ['user'], organizationId }),
    ).resolves.toEqual({ roles: ['user'], permissions: ['reports:read'], ...noOrganization });
  });

  it('uses a membership the caller already read', async () => {
    await resolveAuthorization({
      ...base,
      roles: [],
      organizationId,
      membership: { roles: ['admin'] } as any,
    });

    expect(OrganizationMembership.findOne).not.toHaveBeenCalled();
  });

  it('reads a malformed membership as holding no roles', async () => {
    memberOf('admin');

    const resolved = await resolveAuthorization({ ...base, roles: [], organizationId });

    expect(resolved.organizationRoles).toEqual([]);
  });

  it('grants a recovery session nothing, without reading the mappings', async () => {
    mappings('a:read');
    memberOf(['admin']);

    await expect(
      resolveAuthorization({ ...base, roles: ['x'], organizationId, recovery: true }),
    ).resolves.toEqual({ roles: ['x'], permissions: [], ...noOrganization });
    expect(RolePermission.findAll).not.toHaveBeenCalled();
  });

  it('does not query for a user with no roles', async () => {
    await expect(resolveAuthorization({ ...base, roles: [] })).resolves.toEqual({
      roles: [],
      permissions: [],
      ...noOrganization,
    });
    expect(RolePermission.findAll).not.toHaveBeenCalled();
  });
});

describe('authorizationClaims', () => {
  const resolved = { roles: [], permissions: [], ...noOrganization };

  it('carries a set that fits, with no organization claims outside an organization', () => {
    expect(authorizationClaims({ ...resolved, permissions: ['a:read'] })).toEqual({
      permissions: ['a:read'],
    });
  });

  it('carries the organization claims inside one, even when empty', () => {
    expect(
      authorizationClaims({ ...resolved, organizationId, organizationRoles: ['member'] }),
    ).toEqual({ permissions: [], org_roles: ['member'], org_permissions: [] });
  });

  it('carries a set exactly at the budget', () => {
    const permissions = fittingPermissions();

    expect(authorizationClaims({ ...resolved, permissions })).toEqual({ permissions });
  });

  // A partial list looks complete and denies silently, so nothing is trimmed.
  it('replaces a set over the budget with the marker', () => {
    const permissions = [...fittingPermissions(), 'one-more:action'];

    expect(authorizationClaims({ ...resolved, permissions })).toEqual({
      permissions_omitted: true,
    });
  });

  it('counts the organization claims against the budget', () => {
    expect(
      authorizationClaims({
        ...resolved,
        organizationId,
        organizationRoles: ['member'],
        organizationPermissions: fittingPermissions(),
      }),
    ).toEqual({ permissions_omitted: true });
  });
});

describe('mintAccessToken', () => {
  it('signs the claims into the token', async () => {
    mappingsByKind(['reports:read'], ['projects:write']);
    memberOf(['admin']);

    const minted = await mintAccessToken({
      session: { ...session, organizationId },
      user,
    });
    const claims = decodeJwt(minted.token);

    expect(minted.organizationId).toBe(organizationId);
    expect(claims).toMatchObject({
      sub: user.id,
      sid: session.id,
      roles: ['user'],
      permissions: ['reports:read'],
      org_id: organizationId,
      org_roles: ['admin'],
      org_permissions: ['projects:write'],
    });
    expect(claims.permissions_omitted).toBeUndefined();
  });

  // The reason the claims are separate: a guard on `admin` must not pass for an org admin.
  it('never puts an organization role in roles', async () => {
    memberOf(['admin', 'owner']);

    const { token } = await mintAccessToken({ session: { ...session, organizationId }, user });

    expect(decodeJwt(token).roles).toEqual(['user']);
  });

  it('carries no organization claims without an active organization', async () => {
    const claims = decodeJwt((await mintAccessToken({ session, user })).token);

    expect(claims).not.toHaveProperty('org_id');
    expect(claims).not.toHaveProperty('org_roles');
    expect(claims).not.toHaveProperty('org_permissions');
    expect(Session.update).not.toHaveBeenCalled();
  });

  it('drops the claims and clears the session for a removed member', async () => {
    (OrganizationMembership.findOne as any).mockResolvedValue(null);

    const minted = await mintAccessToken({ session: { ...session, organizationId }, user });

    expect(minted.organizationId).toBeNull();
    expect(decodeJwt(minted.token)).not.toHaveProperty('org_id');
    expect(Session.update).toHaveBeenCalledWith(
      { organizationId: null, hookClaims: null },
      expect.objectContaining({ where: { id: session.id } }),
    );
  });

  it('marks a recovery token and gives it no permissions or organization claims', async () => {
    mappings('reports:read');
    memberOf(['admin']);

    const minted = await mintAccessToken({
      session: { ...session, organizationId, recovery: true },
      user,
    });
    const claims = decodeJwt(minted.token);

    expect(claims.recovery).toBe(true);
    expect(claims.permissions).toEqual([]);
    expect(claims).not.toHaveProperty('org_id');
    // The organization applies again once a factor is enrolled, so the session keeps it.
    expect(minted.organizationId).toBe(organizationId);
    expect(Session.update).not.toHaveBeenCalled();
  });

  it("carries the session's hook claims", async () => {
    const claims = decodeJwt(
      (await mintAccessToken({ session: { ...session, hookClaims: { plan: 'pro' } }, user })).token,
    );

    expect(claims.plan).toBe('pro');
    expect(claims.sub).toBe(user.id);
  });

  it('filters reserved names again, so stored claims cannot replace a protected one', async () => {
    const claims = decodeJwt(
      (
        await mintAccessToken({
          session: {
            ...session,
            hookClaims: { sub: 'someone-else', roles: ['admin'], email: 'x@y.z', plan: 'pro' },
          },
          user,
        })
      ).token,
    );

    expect(claims.sub).toBe(user.id);
    expect(claims.roles).toEqual(['user']);
    expect(claims).not.toHaveProperty('email');
    expect(claims.plan).toBe('pro');
  });

  it('gives a recovery token no hook claims', async () => {
    const claims = decodeJwt(
      (
        await mintAccessToken({
          session: { ...session, recovery: true, hookClaims: { plan: 'pro' } },
          user,
        })
      ).token,
    );

    expect(claims).not.toHaveProperty('plan');
  });

  it('drops hook claims decided for an organization the user has left', async () => {
    (OrganizationMembership.findOne as any).mockResolvedValue(null);

    const claims = decodeJwt(
      (
        await mintAccessToken({
          session: { ...session, organizationId, hookClaims: { plan: 'pro' } },
          user,
        })
      ).token,
    );

    expect(claims).not.toHaveProperty('plan');
  });

  it('carries instance role claims, then organization role claims, then hook claims', async () => {
    memberOf(['admin']);
    vi.mocked(CustomClaim.findAll).mockResolvedValue([
      { sourceKind: 'instance_role', sourceName: 'user', claims: { plan: 'free', region: 'us' } },
      { sourceKind: 'organization_role', sourceName: 'admin', claims: { plan: 'team', seats: 5 } },
    ] as never);

    const claims = decodeJwt(
      (
        await mintAccessToken({
          session: { ...session, organizationId, hookClaims: { seats: 10 } },
          user,
        })
      ).token,
    );

    expect(claims).toMatchObject({ plan: 'team', region: 'us', seats: 10 });
  });

  it('applies organization role claims only while the membership exists', async () => {
    (OrganizationMembership.findOne as any).mockResolvedValue(null);
    vi.mocked(CustomClaim.findAll).mockResolvedValue([
      { sourceKind: 'organization_role', sourceName: 'admin', claims: { plan: 'team' } },
    ] as never);

    await mintAccessToken({ session: { ...session, organizationId }, user });

    const where = vi.mocked(CustomClaim.findAll).mock.calls[0][0]!.where as any;
    const sources = where[Object.getOwnPropertySymbols(where)[0]];
    expect(sources.map((source: any) => source.sourceKind)).toEqual(['instance_role']);
  });

  it('gives a recovery token no custom claims and reads none', async () => {
    await mintAccessToken({ session: { ...session, recovery: true }, user });
    expect(CustomClaim.findAll).not.toHaveBeenCalled();
  });

  it('carries no custom claims, and records why, when the sources together exceed the budget', async () => {
    vi.mocked(CustomClaim.findAll).mockResolvedValue([
      { sourceKind: 'instance_role', sourceName: 'user', claims: { a: 'x'.repeat(700) } },
    ] as never);

    const claims = decodeJwt(
      (
        await mintAccessToken({
          session: { ...session, hookClaims: { b: 'y'.repeat(700) } },
          user,
        })
      ).token,
    );

    expect(claims).not.toHaveProperty('a');
    expect(claims).not.toHaveProperty('b');
    expect(claims.roles).toEqual(['user']);
    expect(AuthEventService.logContext).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: user.id,
        sessionId: session.id,
        type: 'custom_claims_omitted',
        metadata: expect.objectContaining({ budgetBytes: 1024 }),
      }),
    );
  });

  /**
   * ADR 0005 gives custom claims 1 KiB on top of ADR 0004's 1 KiB for permissions, and the
   * adapter cookie would have to hold a token at both. It cannot: only about 136 bytes of custom
   * claims fit beside a full permission set. Pinned as an overflow so the gap stays visible
   * until the budgets or the adapter change, at which point this asserts the cookie fits.
   */
  it('overflows the adapter session cookie at both budgets (open decision)', async () => {
    const longRoles = Array.from({ length: 5 }, (_, index) => `billing:invoices:role-${index}`);
    const authorization = authorizationClaims({
      roles: longRoles,
      permissions: fittingPermissions(),
      ...noOrganization,
    });
    const customClaims: Record<string, string> = {};
    for (let index = 0; ; index++) {
      const next = { ...customClaims, [`claim_${index}`]: 'v'.repeat(40) };
      if (customClaimsByteLength(next) > CUSTOM_CLAIMS_BUDGET_BYTES - 16) break;
      Object.assign(customClaims, next);
    }
    customClaims.pad = '';
    customClaims.pad = 'p'.repeat(
      CUSTOM_CLAIMS_BUDGET_BYTES - customClaimsByteLength(customClaims),
    );

    expect(authorization.permissions_omitted).toBeUndefined();
    expect(customClaimsByteLength(customClaims)).toBe(CUSTOM_CLAIMS_BUDGET_BYTES);

    const token = await signAccessToken(session.id, user.id, longRoles, organizationId, {
      authorization,
      customClaims,
    });

    const cookie = await new SignJWT({
      sub: user.id,
      sessionId: session.id,
      token,
      roles: longRoles,
      email: `${'a'.repeat(64)}@${'b'.repeat(40)}.example.com`,
      phone: '+15555550100',
      organizationId,
    })
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt()
      .setExpirationTime('15m')
      .sign(new TextEncoder().encode('cookie-secret-cookie-secret-cookie'));

    const setCookie = `seamless-access=${cookie}; Max-Age=900; Path=/; HttpOnly; Secure; SameSite=Lax`;

    expect(Buffer.byteLength(token)).toBe(3663);
    expect(Buffer.byteLength(setCookie)).toBe(5670);
    expect(Buffer.byteLength(setCookie)).toBeGreaterThan(4096);
  });

  /**
   * A server adapter signs the whole access token into a cookie alongside the user's details
   * (`issueSessionCookies` in seamless-auth-server), and browsers drop a cookie over 4 KiB,
   * which would sign the user out. This builds that cookie at the worst case the budget allows.
   */
  it('keeps the adapter session cookie under the browser limit at the budget', async () => {
    const longRoles = Array.from({ length: 5 }, (_, index) => `billing:invoices:role-${index}`);
    const authorization = authorizationClaims({
      roles: longRoles,
      permissions: fittingPermissions(),
      ...noOrganization,
    });

    expect(authorization.permissions_omitted).toBeUndefined();

    const token = await signAccessToken(session.id, user.id, longRoles, organizationId, {
      authorization,
    });

    const cookie = await new SignJWT({
      sub: user.id,
      sessionId: session.id,
      token,
      roles: longRoles,
      email: `${'a'.repeat(64)}@${'b'.repeat(40)}.example.com`,
      phone: '+15555550100',
      organizationId,
    })
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt()
      .setExpirationTime('15m')
      .sign(new TextEncoder().encode('cookie-secret-cookie-secret-cookie'));

    const setCookie = `seamless-access=${cookie}; Max-Age=900; Path=/; HttpOnly; Secure; SameSite=Lax`;

    expect(Buffer.byteLength(setCookie)).toBeLessThanOrEqual(4096);
  });
});
