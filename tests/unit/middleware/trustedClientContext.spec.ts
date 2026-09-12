import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/middleware/authenticateServiceToken.js', () => ({
  validateInternalServiceToken: vi.fn(),
}));

describe('applyTrustedClientContext', () => {
  let next: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    vi.clearAllMocks();
    next = vi.fn();
  });

  it('overrides req.ip when a trusted client IP and valid service token are provided', async () => {
    const { validateInternalServiceToken } =
      await import('../../../src/middleware/authenticateServiceToken.js');
    const { applyTrustedClientContext } =
      await import('../../../src/middleware/trustedClientContext.js');

    (validateInternalServiceToken as any).mockResolvedValue({
      sub: 'review-api',
      aud: 'seamless-auth',
      iss: 'seamless-portal-api',
    });

    const req = {
      ip: '10.0.1.25',
      ips: ['10.0.1.25'],
      get: vi.fn((header: string) => {
        if (header === 'x-seamless-client-ip') return '203.0.113.44';
        if (header === 'x-seamless-service-token') return 'Bearer internal-token';
        return undefined;
      }),
    } as any;

    await applyTrustedClientContext(req, {} as any, next);

    expect(req.ip).toBe('203.0.113.44');
    expect(req.ips).toEqual(['203.0.113.44']);
    expect(req.trustedClientIp).toBe('203.0.113.44');
    expect(next).toHaveBeenCalled();
  });

  it('ignores forwarded client IP when the service token is invalid', async () => {
    const { validateInternalServiceToken } =
      await import('../../../src/middleware/authenticateServiceToken.js');
    const { applyTrustedClientContext } =
      await import('../../../src/middleware/trustedClientContext.js');

    (validateInternalServiceToken as any).mockResolvedValue(null);

    const req = {
      ip: '10.0.1.25',
      get: vi.fn((header: string) => {
        if (header === 'x-seamless-client-ip') return '203.0.113.44';
        if (header === 'x-seamless-service-token') return 'Bearer internal-token';
        return undefined;
      }),
    } as any;

    await applyTrustedClientContext(req, {} as any, next);

    expect(req.ip).toBe('10.0.1.25');
    expect(next).toHaveBeenCalled();
  });

  it('continues without changes when neither trusted client header is present', async () => {
    const { validateInternalServiceToken } =
      await import('../../../src/middleware/authenticateServiceToken.js');
    const { applyTrustedClientContext } =
      await import('../../../src/middleware/trustedClientContext.js');

    const req = {
      ip: '10.0.1.25',
      get: vi.fn(() => undefined),
    } as any;

    await applyTrustedClientContext(req, {} as any, next);

    expect(validateInternalServiceToken).not.toHaveBeenCalled();
    expect(req.ip).toBe('10.0.1.25');
    expect(next).toHaveBeenCalled();
  });

  it('ignores a trusted client IP when no service token header is present', async () => {
    const { validateInternalServiceToken } =
      await import('../../../src/middleware/authenticateServiceToken.js');
    const { applyTrustedClientContext } =
      await import('../../../src/middleware/trustedClientContext.js');

    const req = {
      ip: '10.0.1.25',
      get: vi.fn((header: string) => {
        if (header === 'x-seamless-client-ip') return '203.0.113.44';
        return undefined;
      }),
    } as any;

    await applyTrustedClientContext(req, {} as any, next);

    expect(validateInternalServiceToken).not.toHaveBeenCalled();
    expect(req.ip).toBe('10.0.1.25');
    expect(next).toHaveBeenCalled();
  });

  it('accepts a raw (non-Bearer) service token value', async () => {
    const { validateInternalServiceToken } =
      await import('../../../src/middleware/authenticateServiceToken.js');
    const { applyTrustedClientContext } =
      await import('../../../src/middleware/trustedClientContext.js');

    (validateInternalServiceToken as any).mockResolvedValue({
      sub: 'review-api',
      aud: 'seamless-auth',
      iss: 'seamless-portal-api',
    });

    const req = {
      ip: '10.0.1.25',
      get: vi.fn((header: string) => {
        if (header === 'x-seamless-client-ip') return '203.0.113.44';
        if (header === 'x-seamless-service-token') return 'raw-token';
        return undefined;
      }),
    } as any;

    await applyTrustedClientContext(req, {} as any, next);

    expect(validateInternalServiceToken).toHaveBeenCalledWith('raw-token');
    expect(req.ip).toBe('203.0.113.44');
    expect(next).toHaveBeenCalled();
  });

  it('ignores an empty Bearer service token value', async () => {
    const { validateInternalServiceToken } =
      await import('../../../src/middleware/authenticateServiceToken.js');
    const { applyTrustedClientContext } =
      await import('../../../src/middleware/trustedClientContext.js');

    const req = {
      ip: '10.0.1.25',
      get: vi.fn((header: string) => {
        if (header === 'x-seamless-client-ip') return '203.0.113.44';
        if (header === 'x-seamless-service-token') return 'Bearer ';
        return undefined;
      }),
    } as any;

    await applyTrustedClientContext(req, {} as any, next);

    expect(validateInternalServiceToken).not.toHaveBeenCalled();
    expect(req.ip).toBe('10.0.1.25');
    expect(next).toHaveBeenCalled();
  });

  it('ignores a whitespace-only service token value', async () => {
    const { validateInternalServiceToken } =
      await import('../../../src/middleware/authenticateServiceToken.js');
    const { applyTrustedClientContext } =
      await import('../../../src/middleware/trustedClientContext.js');

    const req = {
      ip: '10.0.1.25',
      get: vi.fn((header: string) => {
        if (header === 'x-seamless-client-ip') return '203.0.113.44';
        if (header === 'x-seamless-service-token') return '   ';
        return undefined;
      }),
    } as any;

    await applyTrustedClientContext(req, {} as any, next);

    expect(validateInternalServiceToken).not.toHaveBeenCalled();
    expect(req.ip).toBe('10.0.1.25');
    expect(next).toHaveBeenCalled();
  });

  it('ignores malformed client IP values', async () => {
    const { applyTrustedClientContext } =
      await import('../../../src/middleware/trustedClientContext.js');

    const req = {
      ip: '10.0.1.25',
      get: vi.fn((header: string) => {
        if (header === 'x-seamless-client-ip') return 'not-an-ip';
        if (header === 'x-seamless-service-token') return 'Bearer internal-token';
        return undefined;
      }),
    } as any;

    await applyTrustedClientContext(req, {} as any, next);

    expect(req.ip).toBe('10.0.1.25');
    expect(next).toHaveBeenCalled();
  });

  const browser =
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1';

  function trusted() {
    return {
      sub: 'review-api',
      aud: 'seamless-auth',
      iss: 'seamless-portal-api',
    };
  }

  it('replaces the user agent header with the forwarded one under a valid service token', async () => {
    const { validateInternalServiceToken } =
      await import('../../../src/middleware/authenticateServiceToken.js');
    const { applyTrustedClientContext } =
      await import('../../../src/middleware/trustedClientContext.js');

    (validateInternalServiceToken as any).mockResolvedValue(trusted());

    const req = {
      ip: '10.0.1.25',
      headers: { 'user-agent': 'node' },
      get: vi.fn((header: string) => {
        if (header === 'x-seamless-client-user-agent') return `  ${browser}  `;
        if (header === 'x-seamless-service-token') return 'Bearer internal-token';
        return undefined;
      }),
    } as any;

    await applyTrustedClientContext(req, {} as any, next);

    expect(req.headers['user-agent']).toBe(browser);
    // The address was not forwarded, so it is left alone.
    expect(req.ip).toBe('10.0.1.25');
    expect(req.trustedClientIp).toBeUndefined();
    expect(next).toHaveBeenCalled();
  });

  it('forwards the address and the user agent together', async () => {
    const { validateInternalServiceToken } =
      await import('../../../src/middleware/authenticateServiceToken.js');
    const { applyTrustedClientContext } =
      await import('../../../src/middleware/trustedClientContext.js');

    (validateInternalServiceToken as any).mockResolvedValue(trusted());

    const req = {
      ip: '10.0.1.25',
      headers: { 'user-agent': 'node' },
      get: vi.fn((header: string) => {
        if (header === 'x-seamless-client-ip') return '203.0.113.44';
        if (header === 'x-seamless-client-user-agent') return browser;
        if (header === 'x-seamless-service-token') return 'Bearer internal-token';
        return undefined;
      }),
    } as any;

    await applyTrustedClientContext(req, {} as any, next);

    expect(req.ip).toBe('203.0.113.44');
    expect(req.headers['user-agent']).toBe(browser);
    expect(validateInternalServiceToken).toHaveBeenCalledTimes(1);
  });

  // Either header on its own would let any caller pick its audit identity, so the
  // user agent is gated exactly as the address is.
  it('ignores a forwarded user agent when the service token is invalid or missing', async () => {
    const { validateInternalServiceToken } =
      await import('../../../src/middleware/authenticateServiceToken.js');
    const { applyTrustedClientContext } =
      await import('../../../src/middleware/trustedClientContext.js');

    (validateInternalServiceToken as any).mockResolvedValue(null);

    for (const token of ['Bearer internal-token', undefined]) {
      const req = {
        ip: '10.0.1.25',
        headers: { 'user-agent': 'node' },
        get: vi.fn((header: string) => {
          if (header === 'x-seamless-client-user-agent') return browser;
          if (header === 'x-seamless-service-token') return token;
          return undefined;
        }),
      } as any;

      await applyTrustedClientContext(req, {} as any, next);

      expect(req.headers['user-agent']).toBe('node');
    }
  });

  it('truncates an oversized forwarded user agent and drops a blank one', async () => {
    const { validateInternalServiceToken } =
      await import('../../../src/middleware/authenticateServiceToken.js');
    const { applyTrustedClientContext } =
      await import('../../../src/middleware/trustedClientContext.js');

    (validateInternalServiceToken as any).mockResolvedValue(trusted());

    const long = 'x'.repeat(600);
    const req = {
      ip: '10.0.1.25',
      headers: { 'user-agent': 'node' },
      get: vi.fn((header: string) => {
        if (header === 'x-seamless-client-user-agent') return long;
        if (header === 'x-seamless-service-token') return 'Bearer internal-token';
        return undefined;
      }),
    } as any;

    await applyTrustedClientContext(req, {} as any, next);

    expect(req.headers['user-agent']).toHaveLength(512);

    const blank = {
      ip: '10.0.1.25',
      headers: { 'user-agent': 'node' },
      get: vi.fn((header: string) => {
        if (header === 'x-seamless-client-user-agent') return '   ';
        if (header === 'x-seamless-service-token') return 'Bearer internal-token';
        return undefined;
      }),
    } as any;

    await applyTrustedClientContext(blank, {} as any, next);

    expect(blank.headers['user-agent']).toBe('node');
  });
});
