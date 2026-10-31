import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/models/oidcClients', () => ({
  OidcClient: { findByPk: vi.fn() },
}));

vi.mock('../../../src/models/oidcClientResources', () => ({
  OidcClientResource: { findAll: vi.fn() },
}));

vi.mock('../../../src/models/oidcResources', () => ({
  OidcResource: { findAll: vi.fn() },
}));

vi.mock('../../../src/services/organizationService', () => ({
  getDefaultOrganizationIdForUser: vi.fn(async () => 'org-1'),
}));

import { getSystemConfig } from '../../../src/config/getSystemConfig';
import { OidcClient } from '../../../src/models/oidcClients';
import { OidcClientResource } from '../../../src/models/oidcClientResources';
import { OidcResource } from '../../../src/models/oidcResources';
import { User } from '../../../src/models/users';
import {
  createOidcClientSecretLookup,
  findActiveOidcClient,
  getOidcAccountClaims,
  getOidcClientMetadata,
  getOidcClientResourceScopes,
  verifyOidcClientSecret,
} from '../../../src/services/oidcClientRegistry';

const USER = '11111111-1111-4111-8111-111111111111';

function client(overrides: Record<string, unknown> = {}) {
  return {
    id: 'app',
    name: 'App',
    firstParty: true,
    tokenEndpointAuthMethod: 'private_key_jwt',
    grantTypes: ['authorization_code', 'refresh_token'],
    redirectUris: ['https://app.example.com/cb'],
    postLogoutRedirectUris: [],
    jwks: null,
    jwksUri: 'https://app.example.com/jwks',
    backchannelLogoutUri: null,
    secretLookup: null,
    disabledAt: null,
    ...overrides,
  };
}

describe('findActiveOidcClient', () => {
  it('ignores a disabled client', async () => {
    vi.mocked(OidcClient.findByPk).mockResolvedValue(client({ disabledAt: new Date() }) as never);
    expect(await findActiveOidcClient('app')).toBeNull();
  });
});

describe('getOidcClientMetadata', () => {
  it('maps a web client into library names', async () => {
    vi.mocked(OidcClient.findByPk).mockResolvedValue(client() as never);

    expect(await getOidcClientMetadata('app')).toEqual({
      client_id: 'app',
      client_name: 'App',
      application_type: 'web',
      token_endpoint_auth_method: 'private_key_jwt',
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      redirect_uris: ['https://app.example.com/cb'],
      post_logout_redirect_uris: [],
      jwks_uri: 'https://app.example.com/jwks',
      'urn:seamless:first_party': true,
    });
  });

  it.each(['http://127.0.0.1/cb', 'http://[::1]/cb', 'com.example.app:/cb'])(
    'treats %s as a native redirect',
    async (uri) => {
      vi.mocked(OidcClient.findByPk).mockResolvedValue(client({ redirectUris: [uri] }) as never);
      expect((await getOidcClientMetadata('app'))?.application_type).toBe('native');
    },
  );

  // localhost cannot be registered (RFC 8252 section 8.3), so a stored one is not native.
  it('does not treat a localhost redirect as native', async () => {
    vi.mocked(OidcClient.findByPk).mockResolvedValue(
      client({ redirectUris: ['http://localhost:8080/cb'] }) as never,
    );
    expect((await getOidcClientMetadata('app'))?.application_type).toBe('web');
  });

  it('carries inline keys and back-channel logout, and no code for a service client', async () => {
    const jwks = { keys: [{ kty: 'RSA', kid: 'c1', alg: 'RS256', n: 'n', e: 'AQAB' }] };
    vi.mocked(OidcClient.findByPk).mockResolvedValue(
      client({
        grantTypes: ['client_credentials'],
        jwks,
        jwksUri: null,
        backchannelLogoutUri: 'https://app.example.com/bcl',
        tokenEndpointAuthMethod: 'client_secret_basic',
        secretLookup: 'deadbeefcafe',
      }) as never,
    );

    const metadata = await getOidcClientMetadata('app');

    expect(metadata).toMatchObject({
      response_types: [],
      jwks,
      backchannel_logout_uri: 'https://app.example.com/bcl',
    });
    expect(metadata).not.toHaveProperty('jwks_uri');
    expect(metadata).not.toHaveProperty('client_secret');
    expect(JSON.stringify(metadata)).not.toContain('deadbeefcafe');
  });

  it('returns null for an unknown client', async () => {
    vi.mocked(OidcClient.findByPk).mockResolvedValue(null);
    expect(await getOidcClientMetadata('app')).toBeNull();
  });
});

describe('verifyOidcClientSecret', () => {
  const secret = 'correct horse battery staple';

  beforeEach(() => {
    vi.mocked(getSystemConfig).mockResolvedValue({ allow_client_secrets: true } as never);
    vi.mocked(OidcClient.findByPk).mockResolvedValue(
      client({
        tokenEndpointAuthMethod: 'client_secret_post',
        secretLookup: createOidcClientSecretLookup(secret),
      }) as never,
    );
  });

  it('accepts the stored secret', async () => {
    expect(await verifyOidcClientSecret('app', secret)).toBe(true);
  });

  it('refuses another secret', async () => {
    expect(await verifyOidcClientSecret('app', 'wrong')).toBe(false);
  });

  it('refuses a lookup of another length', async () => {
    vi.mocked(OidcClient.findByPk).mockResolvedValue(
      client({ tokenEndpointAuthMethod: 'client_secret_basic', secretLookup: 'abcd' }) as never,
    );
    expect(await verifyOidcClientSecret('app', secret)).toBe(false);
  });

  it('refuses when the instance does not allow secrets', async () => {
    vi.mocked(getSystemConfig).mockResolvedValue({ allow_client_secrets: false } as never);
    expect(await verifyOidcClientSecret('app', secret)).toBe(false);
  });

  it('refuses a client that is not opted in', async () => {
    vi.mocked(OidcClient.findByPk).mockResolvedValue(
      client({ secretLookup: createOidcClientSecretLookup(secret) }) as never,
    );
    expect(await verifyOidcClientSecret('app', secret)).toBe(false);
  });

  it('refuses a client with no secret or no client at all', async () => {
    vi.mocked(OidcClient.findByPk).mockResolvedValue(
      client({ tokenEndpointAuthMethod: 'client_secret_post' }) as never,
    );
    expect(await verifyOidcClientSecret('app', secret)).toBe(false);

    vi.mocked(OidcClient.findByPk).mockResolvedValue(null);
    expect(await verifyOidcClientSecret('app', secret)).toBe(false);
  });

  it('never derives a lookup that equals a plain hash of the secret', () => {
    expect(createOidcClientSecretLookup('a')).not.toBe(createOidcClientSecretLookup('b'));
    expect(createOidcClientSecretLookup('a')).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('getOidcClientResourceScopes', () => {
  beforeEach(() => {
    vi.mocked(getSystemConfig).mockResolvedValue({
      oidc_issuer: 'https://login.example.com',
    } as never);
    vi.mocked(OidcClient.findByPk).mockResolvedValue(client() as never);
  });

  it('returns the scopes each link allows, never more than the resource defines', async () => {
    vi.mocked(OidcClientResource.findAll).mockResolvedValue([
      { resourceId: 'r1', scopes: ['read', 'admin'] },
      { resourceId: 'r2', scopes: ['x'] },
    ] as never);
    vi.mocked(OidcResource.findAll).mockResolvedValue([
      { id: 'r1', identifier: 'https://api.example.com', scopes: ['read', 'write'] },
    ] as never);

    expect(await getOidcClientResourceScopes('app')).toEqual(
      new Map([['https://api.example.com', new Set(['read'])]]),
    );
  });

  it('skips the resource query when the client has no links', async () => {
    vi.mocked(OidcClientResource.findAll).mockResolvedValue([] as never);

    expect((await getOidcClientResourceScopes('app')).size).toBe(0);
    expect(OidcResource.findAll).not.toHaveBeenCalled();
  });

  it('adds the built-in notices resource for a client with notices enabled', async () => {
    vi.mocked(OidcClient.findByPk).mockResolvedValue(client({ noticesEnabled: true }) as never);
    vi.mocked(OidcClientResource.findAll).mockResolvedValue([] as never);

    expect(await getOidcClientResourceScopes('app')).toEqual(
      new Map([['https://login.example.com/seamless', new Set(['notices:send'])]]),
    );
  });

  it('ignores a stored link to the built-in resource', async () => {
    vi.mocked(OidcClientResource.findAll).mockResolvedValue([
      { resourceId: 'r1', scopes: ['notices:send'] },
    ] as never);
    vi.mocked(OidcResource.findAll).mockResolvedValue([
      { id: 'r1', identifier: 'https://login.example.com/seamless', scopes: ['notices:send'] },
    ] as never);

    expect((await getOidcClientResourceScopes('app')).size).toBe(0);
  });

  it('has no built-in resource without a provider issuer', async () => {
    vi.mocked(getSystemConfig).mockResolvedValue({} as never);
    vi.mocked(OidcClient.findByPk).mockResolvedValue(client({ noticesEnabled: true }) as never);
    vi.mocked(OidcClientResource.findAll).mockResolvedValue([] as never);

    expect((await getOidcClientResourceScopes('app')).size).toBe(0);
  });
});

describe('getOidcAccountClaims', () => {
  it('returns the standard and Seamless claims', async () => {
    vi.mocked(User.findOne).mockResolvedValue({
      id: USER,
      email: 'a@example.com',
      emailVerified: true,
      phone: '+14155552671',
      phoneVerified: false,
      roles: ['user'],
      revoked: false,
    } as never);

    expect(await getOidcAccountClaims(USER)).toEqual({
      sub: USER,
      email: 'a@example.com',
      email_verified: true,
      phone_number: '+14155552671',
      phone_number_verified: false,
      roles: ['user'],
      org_id: 'org-1',
    });
  });

  it('leaves the phone out when there is none, and defaults roles', async () => {
    vi.mocked(User.findOne).mockResolvedValue({
      id: USER,
      email: 'a@example.com',
      emailVerified: false,
      phone: null,
      revoked: false,
    } as never);

    const claims = await getOidcAccountClaims(USER);
    expect(claims).not.toHaveProperty('phone_number');
    expect(claims?.roles).toEqual([]);
  });

  it('returns null for a malformed id, an unknown user or a revoked one', async () => {
    expect(await getOidcAccountClaims('nope')).toBeNull();

    vi.mocked(User.findOne).mockResolvedValue(null);
    expect(await getOidcAccountClaims(USER)).toBeNull();

    vi.mocked(User.findOne).mockResolvedValue({ id: USER, revoked: true } as never);
    expect(await getOidcAccountClaims(USER)).toBeNull();
  });
});
