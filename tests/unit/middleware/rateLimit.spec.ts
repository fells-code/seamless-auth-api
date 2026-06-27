import { beforeEach, describe, expect, it, vi } from 'vitest';
vi.unmock('../../../src/middleware/rateLimit');

vi.mock('../../../src/config/getSystemConfig', () => ({
  getSystemConfig: vi.fn(),
}));

vi.mock('express-rate-limit', () => {
  return {
    default: vi.fn((options = {}) =>
      vi.fn(async (req, res, next) => {
        if (typeof (options as any).limit === 'function') {
          await (options as any).limit(req, res);
        }

        next();
      }),
    ),
  };
});

vi.mock('express-slow-down', () => {
  return {
    default: vi.fn((options = {}) =>
      vi.fn(async (req, res, next) => {
        if (typeof (options as any).delayAfter === 'function') {
          await (options as any).delayAfter(req, res);
        }

        next();
      }),
    ),
  };
});

beforeEach(() => {
  vi.resetModules();
  vi.clearAllMocks();
});

describe('dynamicSlowDown', () => {
  let req: any, res: any, next: any;

  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();

    req = {};
    res = {};
    next = vi.fn();
  });

  it('uses config delay_after', async () => {
    const { getSystemConfig } = await import('../../../src/config/getSystemConfig');
    const slowDown = await import('express-slow-down');

    (getSystemConfig as any).mockResolvedValue({ delay_after: 10 });

    const { dynamicSlowDown } = await import('../../../src/middleware/slowDown');

    await dynamicSlowDown(req, res, next);

    expect(slowDown.default).toHaveBeenCalledWith(
      expect.objectContaining({
        delayAfter: expect.any(Function),
      }),
    );

    expect(getSystemConfig).toHaveBeenCalledTimes(1);
    expect(next).toHaveBeenCalled();
  });

  it('uses default when missing config', async () => {
    const { getSystemConfig } = await import('../../../src/config/getSystemConfig');

    (getSystemConfig as any).mockResolvedValue({});

    const { dynamicSlowDown } = await import('../../../src/middleware/slowDown');

    await dynamicSlowDown(req, res, next);

    expect(next).toHaveBeenCalled();
  });

  it('caches limiter', async () => {
    const { getSystemConfig } = await import('../../../src/config/getSystemConfig');
    const slowDown = await import('express-slow-down');

    (getSystemConfig as any).mockResolvedValue({ delay_after: 10 });

    const { dynamicSlowDown } = await import('../../../src/middleware/slowDown');

    await dynamicSlowDown(req, res, next);
    await dynamicSlowDown(req, res, next);

    expect(slowDown.default).toHaveBeenCalledTimes(1);
  });
});

describe('dynamicRateLimit', () => {
  let req: any, res: any, next: any;

  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();

    req = {};
    res = {};
    next = vi.fn();
  });

  it('uses config rate_limit', async () => {
    const { getSystemConfig } = await import('../../../src/config/getSystemConfig');
    const rateLimit = await import('express-rate-limit');

    (getSystemConfig as any).mockResolvedValue({ rate_limit: 100 });

    const { dynamicRateLimit } = await import('../../../src/middleware/rateLimit');

    await dynamicRateLimit(req, res, next);

    expect(rateLimit.default).toHaveBeenCalledWith(
      expect.objectContaining({
        limit: expect.any(Function),
      }),
    );

    expect(getSystemConfig).toHaveBeenCalledTimes(1);
    expect(next).toHaveBeenCalled();
  });

  it('creates limiter instances once at module initialization', async () => {
    const { getSystemConfig } = await import('../../../src/config/getSystemConfig');
    const rateLimit = await import('express-rate-limit');

    (getSystemConfig as any).mockResolvedValue({ rate_limit: 100 });

    const { dynamicRateLimit } = await import('../../../src/middleware/rateLimit');

    await dynamicRateLimit(req, res, next);
    await dynamicRateLimit(req, res, next);

    expect(rateLimit.default).toHaveBeenCalledTimes(7);
  });
});

describe('magicLinkIpLimiter', () => {
  it('uses fixed limit of 20', async () => {
    const { getSystemConfig } = await import('../../../src/config/getSystemConfig');
    const rateLimit = await import('express-rate-limit');

    (getSystemConfig as any).mockResolvedValue({});

    const { magicLinkIpLimiter } = await import('../../../src/middleware/rateLimit');

    const next = vi.fn();

    // @ts-ignore
    await magicLinkIpLimiter({}, {}, next);

    expect(rateLimit.default).toHaveBeenCalledWith(
      expect.objectContaining({
        limit: 20,
      }),
    );
  });
});

describe('magicLinkEmailLimiter', () => {
  it('uses authenticated email or ip as key', async () => {
    const { getSystemConfig } = await import('../../../src/config/getSystemConfig');
    const rateLimit = await import('express-rate-limit');

    (getSystemConfig as any).mockResolvedValue({});

    const { magicLinkEmailLimiter } = await import('../../../src/middleware/rateLimit');

    const req: any = {
      user: { email: 'Test@Example.com' },
      ip: '127.0.0.1',
    };

    const next = vi.fn();

    // @ts-ignore
    await magicLinkEmailLimiter(req, {}, next);

    expect(rateLimit.default).toHaveBeenCalledWith(
      expect.objectContaining({
        keyGenerator: expect.any(Function),
        legacyHeaders: false,
        limit: 5,
        standardHeaders: true,
        windowMs: 15 * 60 * 1000,
      }),
    );

    const options = (rateLimit.default as any).mock.calls.find(
      ([options]: any[]) => options.keyGenerator,
    )[0];

    expect(options.keyGenerator(req)).toBe('email:test@example.com');
    expect(options.keyGenerator({ ip: '127.0.0.1' })).toBe('ip:127.0.0.1');
  });
});

describe('otpIdentityLimiter', () => {
  it('uses authenticated email or phone as key', async () => {
    const { getSystemConfig } = await import('../../../src/config/getSystemConfig');
    const rateLimit = await import('express-rate-limit');

    (getSystemConfig as any).mockResolvedValue({});

    const { otpIdentityLimiter } = await import('../../../src/middleware/rateLimit');

    const req: any = {
      user: { email: null, phone: '+14155552671' },
      ip: '127.0.0.1',
    };
    const next = vi.fn();

    // @ts-ignore
    await otpIdentityLimiter(req, {}, next);

    const options = (rateLimit.default as any).mock.calls
      .map(([options]: any[]) => options)
      .find((options: any) => options.keyGenerator?.(req) === 'phone:+14155552671');

    expect(options).toEqual(
      expect.objectContaining({
        keyGenerator: expect.any(Function),
        legacyHeaders: false,
        limit: 5,
        standardHeaders: true,
        windowMs: 15 * 60 * 1000,
      }),
    );
    expect(options.keyGenerator({ user: { email: 'Test@Example.com' } })).toBe(
      'email:test@example.com',
    );
  });
});

describe('oauthProviderLimiter', () => {
  it('keys by provider and ip', async () => {
    const { getSystemConfig } = await import('../../../src/config/getSystemConfig');
    const rateLimit = await import('express-rate-limit');

    (getSystemConfig as any).mockResolvedValue({});

    const { oauthProviderLimiter } = await import('../../../src/middleware/rateLimit');

    const req: any = {
      params: { providerId: 'google' },
      ip: '127.0.0.1',
    };
    const next = vi.fn();

    // @ts-ignore
    await oauthProviderLimiter(req, {}, next);

    const options = (rateLimit.default as any).mock.calls
      .map(([options]: any[]) => options)
      .find((options: any) => options.keyGenerator?.(req) === 'google:127.0.0.1');

    expect(options).toEqual(
      expect.objectContaining({
        keyGenerator: expect.any(Function),
        legacyHeaders: false,
        limit: 10,
        standardHeaders: true,
        windowMs: 15 * 60 * 1000,
      }),
    );
  });
});

describe('dynamicJWKSRateLimit', () => {
  it('uses config rate_limit and invokes the cached limiter', async () => {
    const { getSystemConfig } = await import('../../../src/config/getSystemConfig');
    const rateLimit = await import('express-rate-limit');

    (getSystemConfig as any).mockResolvedValue({ rate_limit: 100 });

    const { dynamicJWKSRateLimit } = await import('../../../src/middleware/jwksRateLimit');
    const limiter = (rateLimit.default as any).mock.results[0].value;
    const next = vi.fn();
    const req = {};
    const res = {};

    // @ts-ignore
    await dynamicJWKSRateLimit(req, res, next);

    expect(rateLimit.default).toHaveBeenCalledWith(
      expect.objectContaining({
        limit: expect.any(Function),
      }),
    );
    expect(limiter).toHaveBeenCalledWith(req, res, next);
    expect(getSystemConfig).toHaveBeenCalledTimes(1);
    expect(next).toHaveBeenCalled();
  });
});

describe('rate limiter caches', () => {
  it('keeps dynamic and magic link limiter instances isolated', async () => {
    const { getSystemConfig } = await import('../../../src/config/getSystemConfig');
    const rateLimit = await import('express-rate-limit');

    (getSystemConfig as any).mockResolvedValue({ rate_limit: 100 });

    const { dynamicRateLimit, magicLinkEmailLimiter, magicLinkIpLimiter } =
      await import('../../../src/middleware/rateLimit');

    const next = vi.fn();

    // @ts-ignore
    await dynamicRateLimit({}, {}, next);
    // @ts-ignore
    await magicLinkIpLimiter({}, {}, next);
    // @ts-ignore
    await magicLinkEmailLimiter({}, {}, next);

    expect(rateLimit.default).toHaveBeenCalledTimes(7);
    expect((rateLimit.default as any).mock.calls[0][0]).toEqual(
      expect.objectContaining({
        limit: expect.any(Function),
      }),
    );
    expect((rateLimit.default as any).mock.calls.map(([options]: any[]) => options.limit)).toEqual([
      expect.any(Function),
      20,
      5,
      10,
      5,
      30,
      10,
    ]);
  });
});
