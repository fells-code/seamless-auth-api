import { beforeEach, describe, expect, it, vi } from 'vitest';
vi.unmock('../../../src/middleware/rateLimit');

vi.mock('../../../src/config/getSystemConfig', () => ({
  getSystemConfig: vi.fn(),
}));

vi.mock('express-rate-limit', () => {
  return {
    default: vi.fn(() => vi.fn((req, _res, next) => next())),
  };
});

vi.mock('express-slow-down', () => {
  return {
    default: vi.fn(() => vi.fn((req, _res, next) => next())),
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
        delayAfter: 10,
      }),
    );

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
        max: 100,
      }),
    );

    expect(next).toHaveBeenCalled();
  });

  it('caches limiter', async () => {
    const { getSystemConfig } = await import('../../../src/config/getSystemConfig');
    const rateLimit = await import('express-rate-limit');

    (getSystemConfig as any).mockResolvedValue({ rate_limit: 100 });

    const { dynamicRateLimit } = await import('../../../src/middleware/rateLimit');

    await dynamicRateLimit(req, res, next);
    await dynamicRateLimit(req, res, next);

    expect(rateLimit.default).toHaveBeenCalledTimes(1);
  });
});

describe('magicLinkIpLimiter', () => {
  it('uses fixed max of 20', async () => {
    const { getSystemConfig } = await import('../../../src/config/getSystemConfig');
    const rateLimit = await import('express-rate-limit');

    (getSystemConfig as any).mockResolvedValue({});

    const { magicLinkIpLimiter } = await import('../../../src/middleware/rateLimit');

    const next = vi.fn();

    // @ts-ignore
    await magicLinkIpLimiter({}, {}, next);

    expect(rateLimit.default).toHaveBeenCalledWith(
      expect.objectContaining({
        max: 20,
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
        max: 5,
        standardHeaders: true,
        windowMs: 15 * 60 * 1000,
      }),
    );

    const options = (rateLimit.default as any).mock.calls[0][0];

    expect(options.keyGenerator(req)).toBe('email:test@example.com');
    expect(options.keyGenerator({ ip: '127.0.0.1' })).toBe('ip:127.0.0.1');
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

    expect(rateLimit.default).toHaveBeenCalledTimes(3);
    expect((rateLimit.default as any).mock.calls.map(([options]: any[]) => options.max)).toEqual([
      100, 20, 5,
    ]);
  });
});
