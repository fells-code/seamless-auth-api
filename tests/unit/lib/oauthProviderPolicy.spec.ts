import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const lookup = vi.fn();

vi.mock('node:dns/promises', () => ({ lookup, default: { lookup } }));

const { createServer, get: httpGet } = await import('node:http');
type AddressInfo = import('node:net').AddressInfo;

const {
  assertProviderDestination,
  guardedLookup,
  guardedRequest,
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
  it('allows http and private hosts outside production', () => {
    expect(() => assertProviderDestination('http://10.0.0.5:9000/token', {})).not.toThrow();
  });

  it('refuses http in production and other schemes always', () => {
    expect(() => assertProviderDestination('http://idp.example.com/token', production)).toThrow(
      /https/,
    );
    expect(() => assertProviderDestination('file:///etc/passwd', {})).toThrow(/https/);
  });

  it.each([
    'https://169.254.169.254/token',
    'https://10.0.0.5/token',
    'https://[::1]/token',
    'https://[64:ff9b::a9fe:a9fe]/token',
    'https://[2002:a9fe:a9fe::]/token',
    'https://[::7f00:1]/token',
    'https://[::ffff:127.0.0.1]/token',
    'https://2130706433/token',
    'https://0x7f.1/token',
  ])('refuses the non-public literal %s in production', (url) => {
    expect(() => assertProviderDestination(url, production)).toThrow(OAuthProviderPolicyError);
  });

  it('allows a listed private literal but never link-local', () => {
    const env = { ...production, OAUTH_PROVIDER_PRIVATE_HOSTS: '10.0.0.5,169.254.169.254' };

    expect(() => assertProviderDestination('https://10.0.0.5/token', env)).not.toThrow();
    expect(() => assertProviderDestination('https://169.254.169.254/token', env)).toThrow();
  });

  it('leaves host names to the connection lookup', () => {
    expect(() =>
      assertProviderDestination('https://idp.example.com/token', production),
    ).not.toThrow();
    expect(lookup).not.toHaveBeenCalled();
  });
});

describe('guardedLookup', () => {
  function resolve(hostname: string, env: Record<string, string>, all = false) {
    return new Promise<{ error: Error | null; address: unknown; family?: number }>((done) => {
      (
        guardedLookup(env) as unknown as (
          h: string,
          o: { all?: boolean },
          cb: (error: Error | null, address: unknown, family?: number) => void,
        ) => void
      )(hostname, { all }, (error, address, family) => done({ error, address, family }));
    });
  }

  it('answers with the resolved public address', async () => {
    lookup.mockResolvedValue([{ address: '93.184.216.34', family: 4 }]);

    expect(await resolve('idp.example.com', production)).toEqual({
      error: null,
      address: '93.184.216.34',
      family: 4,
    });
  });

  it('answers every address when the socket asks for all', async () => {
    const addresses = [
      { address: '93.184.216.34', family: 4 },
      { address: '2606:4700::1111', family: 6 },
    ];
    lookup.mockResolvedValue(addresses);

    expect((await resolve('idp.example.com', production, true)).address).toEqual(addresses);
  });

  it('refuses when any address is non-public', async () => {
    lookup.mockResolvedValue([
      { address: '93.184.216.34', family: 4 },
      { address: '64:ff9b::a9fe:a9fe', family: 6 },
    ]);

    expect((await resolve('idp.example.com', production)).error).toBeInstanceOf(
      OAuthProviderPolicyError,
    );
  });

  it('allows a listed on-premises host, but not link-local', async () => {
    const env = { ...production, OAUTH_PROVIDER_PRIVATE_HOSTS: 'IDP.corp.example' };

    lookup.mockResolvedValue([{ address: '10.0.0.7', family: 4 }]);
    expect((await resolve('idp.corp.example', env)).error).toBeNull();

    lookup.mockResolvedValue([{ address: '169.254.169.254', family: 4 }]);
    expect((await resolve('idp.corp.example', env)).error).toBeInstanceOf(OAuthProviderPolicyError);
  });

  it('passes a resolution failure through', async () => {
    lookup.mockRejectedValue(new Error('ENOTFOUND'));

    expect((await resolve('missing.example.com', production)).error?.message).toBe('ENOTFOUND');
  });

  it('is the lookup a real socket uses, so the checked address is the one connected to', async () => {
    const server = createServer((_req, res) => res.end('ok'));
    await new Promise<void>((done) => server.listen(0, '127.0.0.1', done));
    const { port } = server.address() as AddressInfo;
    const get = (env: Record<string, string>) =>
      new Promise<string>((done, fail) => {
        httpGet(`http://idp.corp.example:${port}/`, { lookup: guardedLookup(env) }, (res) => {
          res.resume();
          res.on('end', () => done(String(res.statusCode)));
        }).on('error', fail);
      });

    lookup.mockResolvedValue([{ address: '127.0.0.1', family: 4 }]);

    await expect(get(production)).rejects.toBeInstanceOf(OAuthProviderPolicyError);
    await expect(
      get({ ...production, OAUTH_PROVIDER_PRIVATE_HOSTS: 'idp.corp.example' }),
    ).resolves.toBe('200');

    await new Promise((done) => server.close(done));
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

describe('guardedRequest', () => {
  const allowLocal = { ...production, OAUTH_PROVIDER_PRIVATE_HOSTS: 'idp.corp.example' };
  let port = 0;
  let close: () => Promise<void>;

  beforeEach(async () => {
    lookup.mockResolvedValue([{ address: '127.0.0.1', family: 4 }]);
    const server = createServer((req, res) => {
      let body = '';
      req.on('data', (chunk) => (body += chunk));
      req.on('end', () => {
        if (req.url === '/empty') {
          res.statusCode = 204;
          return res.end();
        }
        if (req.url === '/large') {
          return res.end('x'.repeat(1024 * 1024 + 1));
        }
        if (req.url === '/redirect') {
          res.writeHead(302, { location: 'http://169.254.169.254/' });
          return res.end();
        }
        res.setHeader('content-type', 'application/json');
        res.setHeader('set-cookie', ['a=1', 'b=2']);
        res.end(JSON.stringify({ method: req.method, body, accept: req.headers.accept }));
      });
    });
    await new Promise<void>((done) => server.listen(0, '127.0.0.1', done));
    port = (server.address() as AddressInfo).port;
    close = () => new Promise((done) => server.close(() => done()));
  });

  afterEach(async () => {
    await close();
  });

  const url = (path: string) => new URL(`http://idp.corp.example:${port}${path}`);

  it('sends the method, headers and body, and returns the answer', async () => {
    const response = await guardedRequest(
      url('/token'),
      {
        method: 'POST',
        headers: { Accept: 'application/json' },
        body: new URLSearchParams({ a: 'b' }),
      },
      allowLocal,
    );

    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toBe('application/json');
    expect(await response.json()).toEqual({
      method: 'POST',
      body: 'a=b',
      accept: 'application/json',
    });
  });

  it('returns an empty body for 204', async () => {
    const response = await guardedRequest(url('/empty'), {}, allowLocal);

    expect(response.status).toBe(204);
    expect(await response.text()).toBe('');
  });

  it('hands a redirect back without following it', async () => {
    const response = await guardedRequest(url('/redirect'), {}, allowLocal);

    expect(response.status).toBe(302);
  });

  it('stops reading a response past the size limit', async () => {
    await expect(guardedRequest(url('/large'), {}, allowLocal)).rejects.toThrow(/too large/);
  });

  it('refuses to connect when the host resolves to a non-public address', async () => {
    await expect(guardedRequest(url('/token'), {}, production)).rejects.toBeInstanceOf(
      OAuthProviderPolicyError,
    );
  });
});
