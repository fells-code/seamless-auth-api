import { beforeEach, describe, expect, it, vi } from 'vitest';

const lookup = vi.fn();

vi.mock('node:dns/promises', () => ({ lookup, default: { lookup } }));

const {
  assertProviderDestination,
  clientSecretEnvProblem,
  isNonPublicAddress,
  oauthProviderProblems,
  OAuthProviderPolicyError,
  providerFetch,
} = await import('../../../src/lib/oauthProviderPolicy.js');

const production = { NODE_ENV: 'production' };

function provider(overrides: Record<string, unknown> = {}) {
  return {
    id: 'google',
    name: 'Google',
    enabled: true,
    clientId: 'client',
    clientSecretEnv: 'GOOGLE_CLIENT_SECRET',
    authorizationUrl: 'https://accounts.example.com/authorize',
    tokenUrl: 'https://accounts.example.com/token',
    userInfoUrl: 'https://accounts.example.com/userinfo',
    scopes: ['openid'],
    ...overrides,
  } as never;
}

beforeEach(() => {
  lookup.mockReset();
  vi.unstubAllGlobals();
});

describe('clientSecretEnvProblem', () => {
  it.each(['GOOGLE_CLIENT_SECRET', 'MICROSOFT_CLIENT_SECRET', 'ACME_SSO_CLIENT_SECRET'])(
    'accepts %s',
    (name) => {
      expect(clientSecretEnvProblem(name)).toBeNull();
    },
  );

  it.each([
    'SEAMLESS_SERVICE_TOKEN',
    'API_SERVICE_TOKEN',
    'DB_PASSWORD',
    'DATABASE_URL',
    'SEAMLESS_JWKS_KEY_main_PRIVATE',
    'REFRESH_TOKEN_LOOKUP_SECRET',
    'OAUTH_STATE_SECRET',
    '_CLIENT_SECRET',
    'google_client_secret',
    'GOOGLE_CLIENT_SECRET_EXTRA',
  ])('refuses %s', (name) => {
    expect(clientSecretEnvProblem(name)).toMatch(/_CLIENT_SECRET/);
  });
});

describe('isNonPublicAddress', () => {
  it.each([
    '127.0.0.1',
    '10.1.2.3',
    '172.20.0.1',
    '192.168.1.1',
    '169.254.169.254',
    '100.64.0.1',
    '0.0.0.0',
    '::1',
    'fd00::1',
    'fe80::1',
    '::ffff:127.0.0.1',
  ])('flags %s', (address) => {
    expect(isNonPublicAddress(address)).toBe(true);
  });

  it.each(['8.8.8.8', '2606:4700::1111'])('passes %s', (address) => {
    expect(isNonPublicAddress(address)).toBe(false);
  });
});

describe('oauthProviderProblems', () => {
  it('accepts a public https provider', () => {
    expect(oauthProviderProblems(provider(), production)).toEqual([]);
  });

  it('refuses a scheme other than http(s) in every mode', () => {
    expect(
      oauthProviderProblems(provider({ authorizationUrl: 'javascript:alert(1)//' }), {}),
    ).toEqual(['authorizationUrl must use https']);
  });

  it('allows http and private hosts outside production', () => {
    expect(
      oauthProviderProblems(provider({ tokenUrl: 'http://host.docker.internal:9000/token' }), {
        NODE_ENV: 'development',
      }),
    ).toEqual([]);
  });

  it('requires https in production', () => {
    expect(
      oauthProviderProblems(
        provider({ tokenUrl: 'http://accounts.example.com/token' }),
        production,
      ),
    ).toEqual(['tokenUrl must use https']);
  });

  it('refuses a non-public address literal in production', () => {
    expect(
      oauthProviderProblems(provider({ userInfoUrl: 'https://10.0.0.5/userinfo' }), production),
    ).toEqual([expect.stringMatching(/^userInfoUrl points at a non-public address/)]);
  });

  it('allows a private address the operator lists', () => {
    expect(
      oauthProviderProblems(provider({ jwksUri: 'https://10.0.0.5/jwks' }), {
        ...production,
        OAUTH_PROVIDER_PRIVATE_HOSTS: '10.0.0.5',
      }),
    ).toEqual([]);
  });

  it('refuses link-local even when listed', () => {
    expect(
      oauthProviderProblems(provider({ tokenUrl: 'https://169.254.169.254/token' }), {
        ...production,
        OAUTH_PROVIDER_PRIVATE_HOSTS: '169.254.169.254',
      }),
    ).toHaveLength(1);
  });

  it('reports the secret name and every bad URL together', () => {
    expect(
      oauthProviderProblems(
        provider({ clientSecretEnv: 'DB_PASSWORD', tokenUrl: 'not a url' }),
        production,
      ),
    ).toEqual([expect.stringMatching(/^clientSecretEnv/), 'tokenUrl is not a valid URL']);
  });
});

describe('assertProviderDestination', () => {
  it('skips resolution outside production', async () => {
    await expect(
      assertProviderDestination('http://host.docker.internal:9000/token', {}),
    ).resolves.toBeUndefined();
    expect(lookup).not.toHaveBeenCalled();
  });

  it('refuses a host that resolves to a private address', async () => {
    lookup.mockResolvedValue([{ address: '10.0.0.7', family: 4 }]);

    await expect(
      assertProviderDestination('https://idp.example.com/token', production),
    ).rejects.toBeInstanceOf(OAuthProviderPolicyError);
  });

  it('refuses when any resolved address is non-public', async () => {
    lookup.mockResolvedValue([
      { address: '93.184.216.34', family: 4 },
      { address: '::1', family: 6 },
    ]);

    await expect(
      assertProviderDestination('https://idp.example.com/token', production),
    ).rejects.toThrow(/non-public/);
  });

  it('allows a listed on-premises host', async () => {
    lookup.mockResolvedValue([{ address: '10.0.0.7', family: 4 }]);

    await expect(
      assertProviderDestination('https://idp.corp.example/token', {
        ...production,
        OAUTH_PROVIDER_PRIVATE_HOSTS: 'IDP.corp.example, other.example',
      }),
    ).resolves.toBeUndefined();
  });

  it('refuses a listed host that resolves to link-local', async () => {
    lookup.mockResolvedValue([{ address: '169.254.169.254', family: 4 }]);

    await expect(
      assertProviderDestination('https://idp.corp.example/token', {
        ...production,
        OAUTH_PROVIDER_PRIVATE_HOSTS: 'idp.corp.example',
      }),
    ).rejects.toThrow(/non-public/);
  });

  it('allows a public host', async () => {
    lookup.mockResolvedValue([{ address: '93.184.216.34', family: 4 }]);

    await expect(
      assertProviderDestination(new URL('https://idp.example.com/token'), production),
    ).resolves.toBeUndefined();
  });

  it('refuses http in production and other schemes always', async () => {
    await expect(
      assertProviderDestination('http://idp.example.com/token', production),
    ).rejects.toThrow(/https/);
    await expect(assertProviderDestination('file:///etc/passwd', {})).rejects.toThrow(/https/);
  });
});

describe('providerFetch', () => {
  it('does not follow redirects', async () => {
    const fetch = vi.fn().mockResolvedValue(new Response(null, { status: 302 }));
    vi.stubGlobal('fetch', fetch);

    await expect(
      providerFetch('https://idp.example.com/token', { method: 'POST' }, {}),
    ).rejects.toThrow(/redirect \(302\)/);
    expect(fetch).toHaveBeenCalledWith('https://idp.example.com/token', {
      method: 'POST',
      redirect: 'manual',
    });
  });

  it('returns other responses', async () => {
    const answer = new Response('{}', { status: 400 });
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(answer));

    await expect(providerFetch('https://idp.example.com/token', {}, {})).resolves.toBe(answer);
  });
});
