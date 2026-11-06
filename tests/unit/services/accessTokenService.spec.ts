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

import { getSystemConfig } from '../../../src/config/getSystemConfig.js';
import { signAccessToken } from '../../../src/lib/token.js';
import { RolePermission } from '../../../src/models/rolePermissions.js';
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

describe('resolveAuthorization', () => {
  it('reads what the roles grant, deduplicated and sorted', async () => {
    mappings('b:read', 'a:read', 'b:read');

    await expect(resolveAuthorization({ roles: ['x', 'y'], recovery: false })).resolves.toEqual({
      roles: ['x', 'y'],
      permissions: ['a:read', 'b:read'],
    });
    expect(RolePermission.findAll).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({ roleKind: 'instance' }),
      }),
    );
  });

  it('grants a recovery session nothing, without reading the mappings', async () => {
    mappings('a:read');

    await expect(resolveAuthorization({ roles: ['x'], recovery: true })).resolves.toEqual({
      roles: ['x'],
      permissions: [],
    });
    expect(RolePermission.findAll).not.toHaveBeenCalled();
  });

  it('does not query for a user with no roles', async () => {
    await expect(resolveAuthorization({ roles: [], recovery: false })).resolves.toEqual({
      roles: [],
      permissions: [],
    });
    expect(RolePermission.findAll).not.toHaveBeenCalled();
  });
});

describe('authorizationClaims', () => {
  it('carries a set that fits', () => {
    expect(authorizationClaims({ roles: [], permissions: ['a:read'] })).toEqual({
      permissions: ['a:read'],
    });
  });

  it('carries a set exactly at the budget', () => {
    const permissions = fittingPermissions();

    expect(authorizationClaims({ roles: [], permissions })).toEqual({ permissions });
  });

  // A partial list looks complete and denies silently, so nothing is trimmed.
  it('replaces a set over the budget with the marker', () => {
    const permissions = [...fittingPermissions(), 'one-more:action'];

    expect(authorizationClaims({ roles: [], permissions })).toEqual({
      permissions_omitted: true,
    });
  });
});

describe('mintAccessToken', () => {
  it('signs the claims into the token', async () => {
    mappings('reports:read');

    const claims = decodeJwt(await mintAccessToken({ session, user }));

    expect(claims).toMatchObject({
      sub: user.id,
      sid: session.id,
      roles: ['user'],
      permissions: ['reports:read'],
    });
    expect(claims.permissions_omitted).toBeUndefined();
  });

  it('marks a recovery token and gives it no permissions', async () => {
    mappings('reports:read');

    const claims = decodeJwt(
      await mintAccessToken({ session: { ...session, recovery: true }, user }),
    );

    expect(claims.recovery).toBe(true);
    expect(claims.permissions).toEqual([]);
  });

  /**
   * A server adapter signs the whole access token into a cookie alongside the user's details
   * (`issueSessionCookies` in seamless-auth-server), and browsers drop a cookie over 4 KiB,
   * which would sign the user out. This builds that cookie at the worst case the budget allows.
   */
  it('keeps the adapter session cookie under the browser limit at the budget', async () => {
    mappings(...fittingPermissions());

    const longRoles = Array.from({ length: 5 }, (_, index) => `billing:invoices:role-${index}`);
    const token = await signAccessToken(session.id, user.id, longRoles, session.id, {
      authorization: authorizationClaims(
        await resolveAuthorization({ roles: longRoles, recovery: false }),
      ),
    });

    const cookie = await new SignJWT({
      sub: user.id,
      sessionId: session.id,
      token,
      roles: longRoles,
      email: `${'a'.repeat(64)}@${'b'.repeat(40)}.example.com`,
      phone: '+15555550100',
      organizationId: session.id,
    })
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt()
      .setExpirationTime('15m')
      .sign(new TextEncoder().encode('cookie-secret-cookie-secret-cookie'));

    const setCookie = `seamless-access=${cookie}; Max-Age=900; Path=/; HttpOnly; Secure; SameSite=Lax`;

    expect(Buffer.byteLength(setCookie)).toBeLessThanOrEqual(4096);
  });
});
