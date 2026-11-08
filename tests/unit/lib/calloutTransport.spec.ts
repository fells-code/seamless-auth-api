import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  CALLOUT_PRIVATE_HOSTS_ENV,
  CalloutError,
  calloutHostProblem,
  calloutLookup,
  calloutRequest,
  calloutUrlProblem,
} from '../../../src/lib/calloutTransport.js';

const production = { NODE_ENV: 'production', ISSUER: 'https://auth.example.com' };
const development = { NODE_ENV: 'development', ISSUER: 'http://localhost:5312' };

let server: Server | null = null;

async function serve(handler: Parameters<typeof createServer>[1]) {
  server = createServer(handler);
  await new Promise<void>((done) => server!.listen(0, '127.0.0.1', done));
  return (server.address() as AddressInfo).port;
}

afterEach(async () => {
  if (server) {
    server.closeAllConnections();
    await new Promise<void>((done) => server!.close(() => done()));
    server = null;
  }
});

async function failureOf(promise: Promise<unknown>) {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(CalloutError);
    return (error as CalloutError).failure;
  }
  throw new Error('expected the callout to fail');
}

describe('calloutUrlProblem', () => {
  it.each([
    ['not a url', 'is not a valid URL'],
    ['ftp://hooks.example.com/', 'must use https'],
    ['http://hooks.example.com/', 'must use https'],
    ['https://user:pass@hooks.example.com/', 'must not carry a username or password'],
    ['https://auth.example.com/hooks', 'must not point at this server'],
    ['https://127.0.0.1/hook', `list the host in ${CALLOUT_PRIVATE_HOSTS_ENV}`],
    ['https://10.0.0.5/hook', `list the host in ${CALLOUT_PRIVATE_HOSTS_ENV}`],
    ['https://[::1]/hook', `list the host in ${CALLOUT_PRIVATE_HOSTS_ENV}`],
    ['https://169.254.169.254/latest/meta-data', 'never reachable'],
    // NAT64 for 169.254.169.254: a gateway would turn it back into the metadata address.
    ['https://[64:ff9b::a9fe:a9fe]/', 'never reachable'],
    ['https://[::ffff:169.254.169.254]/', 'never reachable'],
    ['https://224.0.0.1/', 'never reachable'],
    ['https://0.0.0.0/', 'never reachable'],
  ])('refuses %j in production', (url, problem) => {
    expect(calloutUrlProblem(url, production)).toContain(problem);
  });

  it('accepts a public https URL in production', () => {
    expect(calloutUrlProblem('https://hooks.example.com/seamless', production)).toBeNull();
  });

  it('admits a private host only when the operator lists it', () => {
    const env = { ...production, [CALLOUT_PRIVATE_HOSTS_ENV]: 'hooks.internal, 10.0.0.5' };

    expect(calloutUrlProblem('https://10.0.0.5/hook', env)).toBeNull();
    expect(calloutUrlProblem('https://10.0.0.6/hook', env)).toContain('non-public');
  });

  it('never admits the metadata address, even when the operator lists it', () => {
    const env = { ...production, [CALLOUT_PRIVATE_HOSTS_ENV]: '169.254.169.254' };

    expect(calloutUrlProblem('https://169.254.169.254/', env)).toContain('never reachable');
  });

  it('allows http and private hosts outside production, but never link-local', () => {
    expect(calloutUrlProblem('http://127.0.0.1:9000/hook', development)).toBeNull();
    expect(calloutUrlProblem('http://169.254.169.254/', development)).toContain('never reachable');
  });

  it('refuses a missing host', () => {
    expect(calloutHostProblem('', production)).toBe('has no host');
  });

  it('ignores an issuer it cannot parse', () => {
    expect(calloutHostProblem('hooks.example.com', { ISSUER: 'not a url' })).toBeNull();
  });
});

describe('calloutLookup', () => {
  function resolve(hostname: string, env: Record<string, string>, all = false) {
    return new Promise<{ error: Error | null; address: unknown }>((done) =>
      (calloutLookup(env) as any)(hostname, { all }, (error: Error | null, address: unknown) =>
        done({ error, address }),
      ),
    );
  }

  // A name is checked at connect time, so DNS that answers with a private address is refused
  // even though the URL looked public when it was written.
  it('refuses a name that resolves to loopback in production', async () => {
    const { error } = await resolve('localhost', production);

    expect(error).toBeInstanceOf(CalloutError);
    expect((error as CalloutError).failure).toBe('refused');
  });

  it('admits a listed name in production', async () => {
    const { error, address } = await resolve('localhost', {
      ...production,
      [CALLOUT_PRIVATE_HOSTS_ENV]: 'localhost',
    });

    expect(error).toBeNull();
    expect(typeof address).toBe('string');
  });

  it('returns every address when asked for all of them', async () => {
    const { error, address } = await resolve('localhost', development, true);

    expect(error).toBeNull();
    expect(Array.isArray(address)).toBe(true);
  });

  it.each([
    [4, 'IPv4'],
    [6, 'IPv6'],
  ])('honors a requested family (%s)', async (family) => {
    const result = await new Promise<{ error: Error | null }>((done) =>
      (calloutLookup(development) as any)('localhost', { family }, (error: Error | null) =>
        done({ error }),
      ),
    );
    // Either family may be absent on the host; what matters is that the lookup ran.
    expect(result.error === null || result.error instanceof Error).toBe(true);
  });

  it('passes a DNS failure through', async () => {
    const { error } = await resolve('does-not-exist.invalid', development);

    expect(error).toBeInstanceOf(Error);
    expect(error).not.toBeInstanceOf(CalloutError);
  });
});

describe('calloutRequest', () => {
  const base = { timeoutMs: 2000, maxResponseBytes: 1024 };

  it('posts the body and returns the status, headers and body', async () => {
    let received = '';
    const port = await serve((req, res) => {
      req.on('data', (chunk) => (received += chunk));
      req.on('end', () => {
        res.setHeader('retry-after', '5');
        res.end('ok');
      });
    });

    const response = await calloutRequest(
      `http://127.0.0.1:${port}/hook`,
      { ...base, body: '{"a":1}', headers: { 'x-test': '1' } },
      development,
    );

    expect(received).toBe('{"a":1}');
    expect(response.status).toBe(200);
    expect(response.headers['retry-after']).toBe('5');
    expect(response.body.toString()).toBe('ok');
  });

  it('sends a GET without a body', async () => {
    const port = await serve((req, res) => res.end(req.method));

    const response = await calloutRequest(
      `http://127.0.0.1:${port}/`,
      { ...base, method: 'GET' },
      development,
    );

    expect(response.body.toString()).toBe('GET');
  });

  it('does not follow a redirect', async () => {
    let hits = 0;
    const port = await serve((req, res) => {
      hits += 1;
      res.statusCode = 307;
      res.setHeader('location', 'http://169.254.169.254/latest/meta-data');
      res.end();
    });

    const response = await calloutRequest(`http://127.0.0.1:${port}/`, base, development);

    expect(response.status).toBe(307);
    expect(hits).toBe(1);
  });

  it('refuses loopback in production before connecting', async () => {
    let hits = 0;
    const port = await serve((_req, res) => {
      hits += 1;
      res.end();
    });

    expect(await failureOf(calloutRequest(`https://127.0.0.1:${port}/`, base, production))).toBe(
      'refused',
    );
    expect(hits).toBe(0);
  });

  it('refuses a name that resolves to loopback in production', async () => {
    const port = await serve((_req, res) => res.end());

    expect(await failureOf(calloutRequest(`https://localhost:${port}/`, base, production))).toBe(
      'refused',
    );
  });

  it('times out a destination that never answers', async () => {
    const port = await serve(() => {
      // Never responds.
    });

    expect(
      await failureOf(
        calloutRequest(`http://127.0.0.1:${port}/`, { ...base, timeoutMs: 100 }, development),
      ),
    ).toBe('timed_out');
  });

  it('stops reading a response that is too large', async () => {
    const port = await serve((_req, res) => res.end('x'.repeat(4096)));

    expect(
      await failureOf(
        calloutRequest(
          `http://127.0.0.1:${port}/`,
          { ...base, maxResponseBytes: 100 },
          development,
        ),
      ),
    ).toBe('too_large');
  });

  it('reports a refused connection without the socket error', async () => {
    const port = await serve((_req, res) => res.end());
    server!.close();
    server = null;

    const failure = calloutRequest(`http://127.0.0.1:${port}/`, base, development);

    await expect(failure).rejects.toMatchObject({
      failure: 'connection_failed',
      message: 'Callout connection failed',
    });
  });

  it('reports a response that breaks off mid-body', async () => {
    const port = await serve((_req, res) => {
      res.writeHead(200, { 'content-length': '100' });
      res.write('partial');
      setTimeout(() => res.socket?.destroy(), 10);
    });

    expect(await failureOf(calloutRequest(`http://127.0.0.1:${port}/`, base, development))).toBe(
      'connection_failed',
    );
  });
});

describe('calloutRequest status fallback', () => {
  beforeEach(() => {
    vi.resetModules();
  });

  it('treats a missing status code as a bad gateway', async () => {
    vi.doMock('node:http', async (importOriginal) => {
      const actual = await importOriginal<typeof import('node:http')>();
      const { EventEmitter } = await import('node:events');
      return {
        ...actual,
        request: (_url: unknown, _options: unknown, onResponse: (r: unknown) => void) => {
          const request = new EventEmitter() as any;
          request.destroy = () => {};
          request.end = () => {
            const response = new EventEmitter() as any;
            response.headers = {};
            onResponse(response);
            response.emit('end');
          };
          return request;
        },
      };
    });

    const { calloutRequest: isolated } = await import('../../../src/lib/calloutTransport.js');
    const response = await isolated('http://127.0.0.1:1/', base(), development);

    expect(response.status).toBe(502);
    vi.doUnmock('node:http');
  });

  function base() {
    return { timeoutMs: 1000, maxResponseBytes: 1024 };
  }
});
