import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/middleware/authenticateServiceToken.js', () => ({
  validateInternalServiceToken: vi.fn(),
}));

describe('applyTrustedClientIp', () => {
  let next: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    vi.clearAllMocks();
    next = vi.fn();
  });

  it('overrides req.ip when a trusted client IP and valid service token are provided', async () => {
    const { validateInternalServiceToken } =
      await import('../../../src/middleware/authenticateServiceToken.js');
    const { applyTrustedClientIp } = await import('../../../src/middleware/trustedClientIp.js');

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

    await applyTrustedClientIp(req, {} as any, next);

    expect(req.ip).toBe('203.0.113.44');
    expect(req.ips).toEqual(['203.0.113.44']);
    expect(req.trustedClientIp).toBe('203.0.113.44');
    expect(next).toHaveBeenCalled();
  });

  it('ignores forwarded client IP when the service token is invalid', async () => {
    const { validateInternalServiceToken } =
      await import('../../../src/middleware/authenticateServiceToken.js');
    const { applyTrustedClientIp } = await import('../../../src/middleware/trustedClientIp.js');

    (validateInternalServiceToken as any).mockResolvedValue(null);

    const req = {
      ip: '10.0.1.25',
      get: vi.fn((header: string) => {
        if (header === 'x-seamless-client-ip') return '203.0.113.44';
        if (header === 'x-seamless-service-token') return 'Bearer internal-token';
        return undefined;
      }),
    } as any;

    await applyTrustedClientIp(req, {} as any, next);

    expect(req.ip).toBe('10.0.1.25');
    expect(next).toHaveBeenCalled();
  });

  it('ignores malformed client IP values', async () => {
    const { applyTrustedClientIp } = await import('../../../src/middleware/trustedClientIp.js');

    const req = {
      ip: '10.0.1.25',
      get: vi.fn((header: string) => {
        if (header === 'x-seamless-client-ip') return 'not-an-ip';
        if (header === 'x-seamless-service-token') return 'Bearer internal-token';
        return undefined;
      }),
    } as any;

    await applyTrustedClientIp(req, {} as any, next);

    expect(req.ip).toBe('10.0.1.25');
    expect(next).toHaveBeenCalled();
  });
});
