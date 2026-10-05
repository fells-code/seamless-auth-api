import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import { OAuthIdentity } from '../../../src/models/oauthIdentities.js';
import { UserExternalId } from '../../../src/models/userExternalIds.js';
import { User } from '../../../src/models/users.js';
import {
  oauthProfileFromIdToken,
  resolveOAuthUser,
  verifyOAuthIdToken,
} from '../../../src/services/oauthService.js';
import { buildUser } from '../../factories/userFactory.js';

const tenant = '2c0d53c2-a541-452b-b71b-54c7f15e5877';
const issuer = `https://login.microsoftonline.com/${tenant}/v2.0`;
let jwksCounter = 0;

const baseProvider = {
  id: 'microsoft',
  name: 'Microsoft',
  enabled: true,
  clientId: 'client-id',
  clientSecretEnv: 'MICROSOFT_CLIENT_SECRET',
  authorizationUrl: `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/authorize`,
  tokenUrl: `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`,
  userInfoUrl: 'https://graph.microsoft.com/oidc/userinfo',
  scopes: ['openid', 'email', 'profile'],
  redirectUris: [],
  subjectJsonPath: 'sub',
  emailJsonPath: 'email',
  emailVerifiedJsonPath: 'xms_edov',
  allowSignup: true,
  accountLinking: 'email' as const,
  requireEmailVerified: false,
  issuer,
  externalIdSource: 'entra-id',
  externalIdJsonPath: 'oid',
};

let privateKey: CryptoKey;
let otherKey: CryptoKey;
let jwk: Record<string, unknown>;

beforeAll(async () => {
  const pair = await generateKeyPair('RS256');
  privateKey = pair.privateKey;
  jwk = { ...(await exportJWK(pair.publicKey)), kid: 'key-1', alg: 'RS256', use: 'sig' };
  otherKey = (await generateKeyPair('RS256')).privateKey;
});

// Each test gets its own JWKS URL, because the service caches the remote key set by URL.
function providerWithKeys() {
  const jwksUri = `https://login.microsoftonline.com/${tenant}/discovery/v2.0/keys?t=${jwksCounter++}`;
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => new Response(JSON.stringify({ keys: [jwk] }), { status: 200 })),
  );
  return { ...baseProvider, jwksUri };
}

function sign(claims: Record<string, unknown>, opts: { key?: CryptoKey; exp?: string } = {}) {
  return new SignJWT({ nonce: 'nonce-1', ...claims })
    .setProtectedHeader({ alg: 'RS256', kid: 'key-1' })
    .setIssuer(issuer)
    .setAudience('client-id')
    .setSubject('pairwise-sub')
    .setIssuedAt()
    .setExpirationTime(opts.exp ?? '5m')
    .sign(opts.key ?? privateKey);
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe('verifyOAuthIdToken', () => {
  it('returns the claims of a token signed by the provider for this client and sign-in', async () => {
    const provider = providerWithKeys();
    const claims = await verifyOAuthIdToken(
      provider,
      await sign({ oid: 'oid-1', email: 'Ada@Town.example', xms_edov: true }),
      'nonce-1',
    );

    expect(claims).toMatchObject({ sub: 'pairwise-sub', oid: 'oid-1' });
  });

  it.each([
    ['a nonce from another sign-in', async () => sign({ nonce: 'other' })],
    ['a signature from another key', async () => sign({}, { key: otherKey })],
    [
      'another audience',
      async () =>
        new SignJWT({ nonce: 'nonce-1' })
          .setProtectedHeader({ alg: 'RS256', kid: 'key-1' })
          .setIssuer(issuer)
          .setAudience('someone-else')
          .setSubject('s')
          .setIssuedAt()
          .setExpirationTime('5m')
          .sign(privateKey),
    ],
    [
      'another issuer (a different tenant)',
      async () =>
        new SignJWT({ nonce: 'nonce-1' })
          .setProtectedHeader({ alg: 'RS256', kid: 'key-1' })
          .setIssuer('https://login.microsoftonline.com/attacker-tenant/v2.0')
          .setAudience('client-id')
          .setSubject('s')
          .setIssuedAt()
          .setExpirationTime('5m')
          .sign(privateKey),
    ],
    ['an expired token', async () => sign({}, { exp: '-10m' })],
    [
      'a symmetric algorithm',
      async () =>
        new SignJWT({ nonce: 'nonce-1' })
          .setProtectedHeader({ alg: 'HS256' })
          .setIssuer(issuer)
          .setAudience('client-id')
          .setSubject('s')
          .setIssuedAt()
          .setExpirationTime('5m')
          .sign(new TextEncoder().encode('a-shared-secret-of-sufficient-length')),
    ],
  ])('refuses %s', async (_label, build) => {
    const provider = providerWithKeys();

    await expect(verifyOAuthIdToken(provider, await build(), 'nonce-1')).rejects.toMatchObject({
      code: 'oauth_invalid_id_token',
    });
  });

  it('refuses a token for several audiences that names another authorized party', async () => {
    const provider = providerWithKeys();
    const token = await new SignJWT({ nonce: 'nonce-1', azp: 'other-client' })
      .setProtectedHeader({ alg: 'RS256', kid: 'key-1' })
      .setIssuer(issuer)
      .setAudience(['client-id', 'other-client'])
      .setSubject('s')
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(privateKey);

    await expect(verifyOAuthIdToken(provider, token, 'nonce-1')).rejects.toMatchObject({
      code: 'oauth_invalid_id_token',
    });
  });

  it('refuses a token without an expiry', async () => {
    const provider = providerWithKeys();
    const token = await new SignJWT({ nonce: 'nonce-1' })
      .setProtectedHeader({ alg: 'RS256', kid: 'key-1' })
      .setIssuer(issuer)
      .setAudience('client-id')
      .setSubject('s')
      .setIssuedAt()
      .sign(privateKey);

    await expect(verifyOAuthIdToken(provider, token, 'nonce-1')).rejects.toMatchObject({
      code: 'oauth_invalid_id_token',
    });
  });

  it('refuses a token response without an ID token', async () => {
    await expect(
      verifyOAuthIdToken(providerWithKeys(), undefined, 'nonce-1'),
    ).rejects.toMatchObject({ code: 'oauth_invalid_id_token' });
  });

  it('refuses a provider with an issuer but no key set', async () => {
    await expect(
      verifyOAuthIdToken({ ...baseProvider, jwksUri: undefined }, 'x.y.z', 'nonce-1'),
    ).rejects.toThrow(/issuer and jwksUri/);
  });
});

describe('oauthProfileFromIdToken', () => {
  const claims = { sub: 'pairwise-sub', oid: 'oid-1', email: 'Ada@Town.example', xms_edov: true };

  it('reads the profile and the imported-user claim', () => {
    expect(oauthProfileFromIdToken(baseProvider, claims)).toMatchObject({
      subject: 'pairwise-sub',
      email: 'ada@town.example',
      emailVerified: true,
      externalId: 'oid-1',
    });
  });

  it('carries no external id for a provider that does not link imported users', () => {
    const profile = oauthProfileFromIdToken(
      { ...baseProvider, externalIdSource: undefined },
      claims,
    );

    expect(profile.externalId).toBeUndefined();
  });
});

describe('resolveOAuthUser with imported users', () => {
  const profile = {
    subject: 'pairwise-sub',
    email: 'ada@town.example',
    externalId: 'oid-1',
    raw: {},
  };

  it('links a first sign-in to the user imported under that id, without trusting the email', async () => {
    const imported = buildUser({ id: 'imported', email: 'ada@town.example', verified: false });
    (OAuthIdentity.findOne as any).mockResolvedValue(null);
    (UserExternalId.findOne as any).mockResolvedValue({ userId: 'imported' });
    (User.findByPk as any).mockResolvedValue(imported);
    (OAuthIdentity.findOrCreate as any).mockResolvedValue([]);

    await expect(resolveOAuthUser(baseProvider, profile)).resolves.toBe(imported);

    expect(UserExternalId.findOne).toHaveBeenCalledWith({
      where: { source: 'entra-id', externalId: 'oid-1' },
    });
    const [values] = (imported.update as any).mock.calls[0];
    expect(values).toMatchObject({ verified: true });
    expect(values).not.toHaveProperty('emailVerified');
    expect(User.findOne).not.toHaveBeenCalled();
  });

  it('falls back to the email rules when no imported user matches', async () => {
    (OAuthIdentity.findOne as any).mockResolvedValue(null);
    (UserExternalId.findOne as any).mockResolvedValue(null);
    (User.findOne as any).mockResolvedValue(buildUser({ email: 'ada@town.example' }));

    await expect(resolveOAuthUser(baseProvider, profile)).rejects.toMatchObject({
      code: 'oauth_email_not_verified',
    });
    expect(OAuthIdentity.findOrCreate).not.toHaveBeenCalled();
  });

  it('ignores the external id when the provider does not link imported users', async () => {
    (OAuthIdentity.findOne as any).mockResolvedValue(null);
    (User.findOne as any).mockResolvedValue(null);

    await expect(
      resolveOAuthUser({ ...baseProvider, externalIdSource: undefined }, profile),
    ).rejects.toMatchObject({ code: 'oauth_email_not_verified' });
    expect(UserExternalId.findOne).not.toHaveBeenCalled();
  });
});
