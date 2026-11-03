import { generateKeyPairSync } from 'crypto';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/models/oidcClients', () => ({
  OidcClient: { findByPk: vi.fn() },
}));

vi.mock('../../../src/models/oidcClientResources', () => ({
  OidcClientResource: { findAll: vi.fn(async () => []) },
}));

vi.mock('../../../src/models/oidcResources', () => ({
  OidcResource: { findAll: vi.fn(async () => []) },
}));

vi.mock('../../../src/services/oidcProviderKeys', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/services/oidcProviderKeys')>()),
  getActiveOidcSigningKey: vi.fn(),
}));

import { getSystemConfig } from '../../../src/config/getSystemConfig';
import { OidcClient } from '../../../src/models/oidcClients';
import {
  createOidcClientSecretLookup,
  findActiveOidcClient,
  getOidcClientMetadata,
  verifyOidcClientSecret,
} from '../../../src/services/oidcClientRegistry';
import { getActiveOidcSigningKey } from '../../../src/services/oidcProviderKeys';
import { signForOidcEdge } from '../../../src/services/oidcSigning';

// ADR 0001, D10: third_party_clients_enabled gates third-party clients entirely, so turning
// it off must stop the API serving and signing for the ones that already exist.

const ISSUER = 'https://login.example.com';
const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });

function client(overrides: Record<string, unknown> = {}) {
  return {
    id: 'svc',
    name: 'Partner',
    firstParty: false,
    clientType: 'confidential',
    tokenEndpointAuthMethod: 'client_secret_basic',
    grantTypes: ['authorization_code', 'client_credentials'],
    redirectUris: ['https://partner.example/cb'],
    postLogoutRedirectUris: [],
    jwks: null,
    jwksUri: null,
    backchannelLogoutUri: null,
    secretLookup: createOidcClientSecretLookup('s3cret'),
    noticesEnabled: true,
    disabledAt: null,
    ...overrides,
  };
}

function config(thirdParty: boolean) {
  vi.mocked(getSystemConfig).mockResolvedValue({
    oidc_issuer: ISSUER,
    allow_client_secrets: true,
    third_party_clients_enabled: thirdParty,
  } as never);
}

function b64(value: unknown) {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

const clientCredentials = () => ({
  kind: 'client_credentials' as const,
  kid: 'k1',
  clientId: 'svc',
  signingInput: `${b64({ alg: 'RS256', kid: 'k1', typ: 'at+jwt' })}.${b64({
    iss: ISSUER,
    sub: 'svc',
    client_id: 'svc',
    aud: `${ISSUER}/seamless`,
    scope: 'notices:send',
    exp: Math.floor(Date.now() / 1000) + 600,
  })}`,
});

beforeEach(() => {
  vi.mocked(getActiveOidcSigningKey).mockReturnValue(privateKey);
});

describe('third_party_clients_enabled off', () => {
  beforeEach(() => {
    config(false);
    vi.mocked(OidcClient.findByPk).mockResolvedValue(client() as never);
  });

  it('treats an existing third-party client as inactive', async () => {
    expect(await findActiveOidcClient('svc')).toBeNull();
  });

  it('does not serve its metadata to the edge', async () => {
    expect(await getOidcClientMetadata('svc')).toBeNull();
  });

  it('does not verify its secret', async () => {
    expect(await verifyOidcClientSecret('svc', 's3cret')).toBe(false);
  });

  it('does not sign for it', async () => {
    expect(await signForOidcEdge(clientCredentials())).toEqual({
      ok: false,
      code: 'client_inactive',
    });
  });

  it('still serves a first-party client', async () => {
    vi.mocked(OidcClient.findByPk).mockResolvedValue(client({ firstParty: true }) as never);

    expect(await findActiveOidcClient('svc')).not.toBeNull();
    expect(await getOidcClientMetadata('svc')).toEqual(
      expect.objectContaining({ client_id: 'svc' }),
    );
  });
});

describe('third_party_clients_enabled on', () => {
  beforeEach(() => {
    config(true);
    vi.mocked(OidcClient.findByPk).mockResolvedValue(client() as never);
  });

  it('serves and signs for a third-party client', async () => {
    expect(await findActiveOidcClient('svc')).not.toBeNull();
    expect(await verifyOidcClientSecret('svc', 's3cret')).toBe(true);
    expect(await signForOidcEdge(clientCredentials())).toEqual(
      expect.objectContaining({ ok: true }),
    );
  });
});
