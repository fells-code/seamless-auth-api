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

  it('scales the delay linearly with the number of hits', async () => {
    const { getSystemConfig } = await import('../../../src/config/getSystemConfig');
    const slowDown = await import('express-slow-down');

    (getSystemConfig as any).mockResolvedValue({ delay_after: 10 });

    await import('../../../src/middleware/slowDown');

    const options = (slowDown.default as any).mock.calls[0][0];

    const request = { slowDown: { limit: 10 } };

    expect(options.delayMs(10, request)).toBe(0);
    expect(options.delayMs(13, request)).toBe(3000);
    expect(options.maxDelayMs).toBe(20000);
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

  it('falls back to the default limit when config omits rate_limit', async () => {
    const { getSystemConfig } = await import('../../../src/config/getSystemConfig');
    const rateLimit = await import('express-rate-limit');

    (getSystemConfig as any).mockResolvedValue({});

    const { dynamicRateLimit } = await import('../../../src/middleware/rateLimit');

    await dynamicRateLimit(req, res, next);

    const limitFn = (rateLimit.default as any).mock.calls[0][0].limit;

    await expect(limitFn(req, res)).resolves.toBe(50);
    expect(next).toHaveBeenCalled();
  });

  it('creates the general limiter once at module initialization', async () => {
    const { getSystemConfig } = await import('../../../src/config/getSystemConfig');
    const rateLimit = await import('express-rate-limit');
    (getSystemConfig as any).mockResolvedValue({ rate_limit: 100 });
    const { dynamicRateLimit } = await import('../../../src/middleware/rateLimit');

    await dynamicRateLimit(req, res, next);
    await dynamicRateLimit(req, res, next);

    // The flow limiters are built on first use, per configured window, not here.
    expect(rateLimit.default).toHaveBeenCalledTimes(1);
  });
});

// The six flow limiters read `flow_rate_limits` from system config. With no
// value configured they carry the constants they had before the key existed.
const FLOW_LIMITS = {
  windowSeconds: 900,
  otp: { perIp: 10, perIdentity: 5 },
  magicLink: { perIp: 20, perIdentity: 5 },
  oauth: { perIp: 30, perProvider: 10 },
};

async function loadFlowLimiters(config: Record<string, unknown> = {}) {
  const { getSystemConfig } = await import('../../../src/config/getSystemConfig');
  const rateLimit = await import('express-rate-limit');
  (getSystemConfig as any).mockResolvedValue(config);
  const limiters = await import('../../../src/middleware/rateLimit');
  return { getSystemConfig, rateLimit, limiters };
}

/** The options of the last limiter express-rate-limit was asked to build. */
function lastOptions(rateLimit: any) {
  const calls = rateLimit.default.mock.calls;
  return calls[calls.length - 1][0];
}

describe('flow limiters', () => {
  it.each([
    ['magicLinkIpLimiter', 20],
    ['magicLinkEmailLimiter', 5],
    ['otpIpLimiter', 10],
    ['otpIdentityLimiter', 5],
    ['oauthIpLimiter', 30],
    ['oauthProviderLimiter', 10],
  ] as const)(
    '%s keeps its historical limit when nothing is configured',
    async (name, expected) => {
      const { rateLimit, limiters } = await loadFlowLimiters();
      const next = vi.fn();

      // @ts-ignore
      await limiters[name]({ ip: '1.1.1.1', params: {} }, {}, next);

      const options = lastOptions(rateLimit);
      expect(options).toEqual(
        expect.objectContaining({
          legacyHeaders: false,
          standardHeaders: true,
          windowMs: 15 * 60 * 1000,
          limit: expect.any(Function),
        }),
      );
      await expect(options.limit()).resolves.toBe(expected);
      expect(next).toHaveBeenCalled();
    },
  );

  it('reads the configured per-IP value for a flow and leaves the others alone', async () => {
    const { rateLimit, limiters } = await loadFlowLimiters({
      flow_rate_limits: { ...FLOW_LIMITS, otp: { perIp: 500, perIdentity: 5 } },
    });

    // @ts-ignore
    await limiters.otpIpLimiter({}, {}, vi.fn());
    const otpIp = lastOptions(rateLimit);
    // @ts-ignore
    await limiters.otpIdentityLimiter({ body: { email: 'a@b.c' } }, {}, vi.fn());
    const otpIdentity = lastOptions(rateLimit);

    await expect(otpIp.limit()).resolves.toBe(500);
    await expect(otpIdentity.limit()).resolves.toBe(5);
  });

  it('takes a changed limit on the next hit without rebuilding the limiter', async () => {
    const { getSystemConfig, rateLimit, limiters } = await loadFlowLimiters({
      flow_rate_limits: FLOW_LIMITS,
    });

    // @ts-ignore
    await limiters.magicLinkIpLimiter({}, {}, vi.fn());
    const built = rateLimit.default.mock.calls.length;
    const options = lastOptions(rateLimit);

    (getSystemConfig as any).mockResolvedValue({
      flow_rate_limits: { ...FLOW_LIMITS, magicLink: { perIp: 75, perIdentity: 5 } },
    });
    // @ts-ignore
    await limiters.magicLinkIpLimiter({}, {}, vi.fn());

    expect(rateLimit.default.mock.calls.length).toBe(built);
    await expect(options.limit()).resolves.toBe(75);
  });

  it('builds one limiter per configured window', async () => {
    const { getSystemConfig, rateLimit, limiters } = await loadFlowLimiters({
      flow_rate_limits: FLOW_LIMITS,
    });

    // @ts-ignore
    await limiters.oauthIpLimiter({}, {}, vi.fn());
    // @ts-ignore
    await limiters.oauthIpLimiter({}, {}, vi.fn());
    const withDefaultWindow = rateLimit.default.mock.calls.length;

    (getSystemConfig as any).mockResolvedValue({
      flow_rate_limits: { ...FLOW_LIMITS, windowSeconds: 60 },
    });
    // @ts-ignore
    await limiters.oauthIpLimiter({}, {}, vi.fn());

    expect(rateLimit.default.mock.calls.length).toBe(withDefaultWindow + 1);
    expect(lastOptions(rateLimit).windowMs).toBe(60 * 1000);
  });
});

describe('magicLinkEmailLimiter', () => {
  it('uses authenticated email or ip as key', async () => {
    const { rateLimit, limiters } = await loadFlowLimiters();
    const req: any = {
      user: { email: 'Test@Example.com' },
      ip: '127.0.0.1',
    };

    // @ts-ignore
    await limiters.magicLinkEmailLimiter(req, {}, vi.fn());

    const options = lastOptions(rateLimit);
    expect(options.keyGenerator(req)).toBe('email:test@example.com');
    expect(options.keyGenerator({ ip: '127.0.0.1' })).toBe('ip:127.0.0.1');
  });
});

describe('otpIdentityLimiter', () => {
  it('uses authenticated email or phone as key', async () => {
    const { rateLimit, limiters } = await loadFlowLimiters();
    const req: any = {
      user: { email: null, phone: '+14155552671' },
      ip: '127.0.0.1',
    };

    // @ts-ignore
    await limiters.otpIdentityLimiter(req, {}, vi.fn());

    const options = lastOptions(rateLimit);
    expect(options.keyGenerator(req)).toBe('phone:+14155552671');
    expect(options.keyGenerator({ user: { email: 'Test@Example.com' } })).toBe(
      'email:test@example.com',
    );
  });
});

describe('rate limiter key generators', () => {
  async function keyGenerators() {
    const { rateLimit, limiters } = await loadFlowLimiters();
    const keyOf = async (limiter: any) => {
      await limiter({ params: {} }, {}, vi.fn());
      return lastOptions(rateLimit).keyGenerator;
    };

    return {
      magicLink: await keyOf(limiters.magicLinkEmailLimiter),
      otp: await keyOf(limiters.otpIdentityLimiter),
      oauth: await keyOf(limiters.oauthProviderLimiter),
    };
  }

  it('falls back through body, query, socket, and unknown for magic links', async () => {
    const { magicLink } = await keyGenerators();

    expect(magicLink({ body: { email: 'B@x.com' } })).toBe('email:b@x.com');
    expect(magicLink({ query: { email: 'Q@x.com' } })).toBe('email:q@x.com');
    expect(magicLink({ socket: { remoteAddress: '1.2.3.4' } })).toBe('ip:1.2.3.4');
    expect(magicLink({ socket: {} })).toBe('ip:unknown');
  });

  it('falls back through email, phone, socket, and unknown for OTP', async () => {
    const { otp } = await keyGenerators();

    expect(otp({ body: { email: 'B@x.com' } })).toBe('email:b@x.com');
    expect(otp({ body: { phone: '+14155550000' } })).toBe('phone:+14155550000');
    expect(otp({ socket: { remoteAddress: '1.2.3.4' } })).toBe('ip:1.2.3.4');
    expect(otp({ socket: {} })).toBe('ip:unknown');
  });

  it('falls back to the unknown provider and unknown IP for OAuth flows', async () => {
    const { oauth } = await keyGenerators();

    expect(oauth({ params: {}, socket: { remoteAddress: '1.2.3.4' } })).toBe(
      'unknown-provider:1.2.3.4',
    );
    expect(oauth({ params: { providerId: 'google' }, socket: {} })).toBe('google:unknown');
  });
});

describe('oauthProviderLimiter', () => {
  it('keys by provider and ip', async () => {
    const { rateLimit, limiters } = await loadFlowLimiters();
    const req: any = {
      params: { providerId: 'google' },
      ip: '127.0.0.1',
    };

    // @ts-ignore
    await limiters.oauthProviderLimiter(req, {}, vi.fn());

    expect(lastOptions(rateLimit).keyGenerator(req)).toBe('google:127.0.0.1');
  });
});

describe('refusal body', () => {
  // Six of these set no message at all and inherited express-rate-limit's own string
  // default, so grepping for the string found three of the nine sites. Asserted across
  // every constructed limiter rather than per-limiter for that reason.
  it('gives every limiter the JSON error shape', async () => {
    const { limiters, rateLimit } = await loadFlowLimiters();
    await import('../../../src/middleware/jwksRateLimit');

    for (const name of [
      'magicLinkIpLimiter',
      'magicLinkEmailLimiter',
      'otpIpLimiter',
      'otpIdentityLimiter',
      'oauthIpLimiter',
      'oauthProviderLimiter',
    ] as const) {
      // @ts-ignore
      await limiters[name]({ ip: '1.1.1.1', params: {} }, {}, vi.fn());
    }

    const messages = (rateLimit.default as any).mock.calls.map(
      ([options]: any[]) => options.message,
    );
    expect(messages).toHaveLength(8);
    for (const message of messages) {
      expect(message).toEqual({ error: 'Too many requests, please try again later' });
    }
  });

  // express-slow-down replaces the handler with one that only delays and calls next,
  // so it never answers a request and a message there could not be read.
  it('sets no message on the slow-down, which never answers', async () => {
    const { getSystemConfig } = await import('../../../src/config/getSystemConfig');
    const slowDown = await import('express-slow-down');

    (getSystemConfig as any).mockResolvedValue({});

    await import('../../../src/middleware/slowDown');

    expect((slowDown.default as any).mock.calls[0][0]).not.toHaveProperty('message');
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
  it('keeps the general limiter and each flow limiter as separate instances', async () => {
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
    // @ts-ignore
    await magicLinkIpLimiter({}, {}, next);

    // One general limiter at load, then one per flow limiter on first use, and a
    // repeat hit reuses the instance it built.
    expect(rateLimit.default).toHaveBeenCalledTimes(3);
    const limits = await Promise.all(
      (rateLimit.default as any).mock.calls.map(([options]: any[]) => options.limit()),
    );
    expect(limits).toEqual([100, 20, 5]);
  });
});
