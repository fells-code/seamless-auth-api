import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/services/accessTokenService', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/services/accessTokenService')>()),
  resolveAuthorization: vi.fn(),
}));

vi.mock('../../../src/services/customClaimService', () => ({
  resolveCustomClaims: vi.fn(),
}));

import { User } from '../../../src/models/users';
import { resolveAuthorization } from '../../../src/services/accessTokenService';
import { AuthEventService } from '../../../src/services/authEventService';
import { resolveCustomClaims } from '../../../src/services/customClaimService';
import { getOidcAccountClaims, providerTokenClaims } from '../../../src/services/oidcAccountClaims';

const USER = '11111111-1111-4111-8111-111111111111';
const SESSION = '22222222-2222-4222-8222-222222222222';

const session = {
  id: SESSION,
  userId: USER,
  organizationId: 'org-1',
  recovery: false,
  hookClaims: { seats: 10 },
};

const member = {
  roles: ['user'],
  permissions: ['orders:read'],
  organizationId: 'org-1',
  organizationRoles: ['member'],
  organizationPermissions: ['projects:read'],
};

function user(overrides: Record<string, unknown> = {}) {
  return {
    id: USER,
    email: 'a@example.com',
    emailVerified: true,
    phone: '+14155552671',
    phoneVerified: false,
    roles: ['user'],
    revoked: false,
    ...overrides,
  };
}

beforeEach(() => {
  vi.mocked(User.findOne).mockResolvedValue(user() as never);
  vi.mocked(resolveAuthorization).mockResolvedValue(member);
  vi.mocked(resolveCustomClaims).mockResolvedValue({ tier: 'gold', seats: 10 });
});

describe('getOidcAccountClaims', () => {
  it('returns the identity, permission and custom claims for the session and client', async () => {
    expect(await getOidcAccountClaims(session, 'app')).toEqual({
      sub: USER,
      email: 'a@example.com',
      email_verified: true,
      phone_number: '+14155552671',
      phone_number_verified: false,
      roles: ['user'],
      org_id: 'org-1',
      permissions: ['orders:read'],
      org_roles: ['member'],
      org_permissions: ['projects:read'],
      customClaims: { tier: 'gold', seats: 10 },
    });
    expect(resolveAuthorization).toHaveBeenCalledWith({
      userId: USER,
      roles: ['user'],
      organizationId: 'org-1',
      recovery: false,
    });
    expect(resolveCustomClaims).toHaveBeenCalledWith({
      roles: ['user'],
      organizationRoles: ['member'],
      clientId: 'app',
      hookClaims: { seats: 10 },
    });
  });

  it("names the session's organization only while the user is still a member", async () => {
    vi.mocked(resolveAuthorization).mockResolvedValue({
      ...member,
      organizationId: null,
      organizationRoles: [],
      organizationPermissions: [],
    });

    const claims = await getOidcAccountClaims(session, 'app');

    expect(claims).toMatchObject({ org_id: null, permissions: ['orders:read'] });
    expect(claims).not.toHaveProperty('org_roles');
    // The hook decided its claims for that organization.
    expect(vi.mocked(resolveCustomClaims).mock.calls[0][0].hookClaims).toBeNull();
  });

  it('leaves the phone out when there is none, and defaults roles', async () => {
    vi.mocked(User.findOne).mockResolvedValue(user({ phone: null, roles: null }) as never);

    const claims = await getOidcAccountClaims({ ...session, organizationId: null }, 'app');

    expect(claims).not.toHaveProperty('phone_number');
    expect(claims?.roles).toEqual([]);
  });

  it('carries no permission or custom claims for a recovery session', async () => {
    vi.mocked(resolveAuthorization).mockResolvedValue({
      ...member,
      permissions: [],
      organizationId: null,
      organizationRoles: [],
      organizationPermissions: [],
    });

    const claims = await getOidcAccountClaims({ ...session, recovery: true }, 'app');

    expect(claims).not.toHaveProperty('permissions');
    expect(claims?.customClaims).toEqual({});
    expect(resolveCustomClaims).not.toHaveBeenCalled();
  });

  it('applies the shared budget, permissions first, and records an omission only when asked', async () => {
    vi.mocked(resolveCustomClaims).mockResolvedValue({ blob: 'x'.repeat(1100) });

    const claims = await getOidcAccountClaims(session, 'app');
    expect(claims).toMatchObject({ permissions_omitted: true, customClaims: {} });
    expect(claims).not.toHaveProperty('permissions');
    expect(AuthEventService.logContext).not.toHaveBeenCalled();

    await getOidcAccountClaims(session, 'app', { recordOmission: true });
    expect(AuthEventService.logContext).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: USER,
        sessionId: SESSION,
        type: 'custom_claims_omitted',
        metadata: expect.objectContaining({ budgetBytes: 1024, clientId: 'app' }),
      }),
    );
  });

  it('returns null for a malformed id, an unknown user or a revoked one', async () => {
    expect(await getOidcAccountClaims({ ...session, userId: 'nope' }, 'app')).toBeNull();

    vi.mocked(User.findOne).mockResolvedValue(null);
    expect(await getOidcAccountClaims(session, 'app')).toBeNull();

    vi.mocked(User.findOne).mockResolvedValue(user({ revoked: true }) as never);
    expect(await getOidcAccountClaims(session, 'app')).toBeNull();
  });
});

describe('providerTokenClaims', () => {
  it('flattens the custom claims, never over a Seamless claim', () => {
    expect(
      providerTokenClaims({
        sub: USER,
        roles: ['user'],
        org_id: null,
        customClaims: { tier: 'gold', roles: ['admin'] },
      }),
    ).toEqual({ sub: USER, roles: ['user'], org_id: null, tier: 'gold' });
  });
});
