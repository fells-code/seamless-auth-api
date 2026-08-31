import { Application } from 'express';
import request from 'supertest';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// tests/setup/mocks.ts replaces both limiters with pass-throughs for the whole suite,
// which is the second reason nothing exercises them. Opt this file back into the real
// ones, the same way tests/unit/middleware/rateLimit.spec.ts does.
vi.unmock('../../../src/middleware/rateLimit');

import { getSystemConfig } from '../../../src/config/getSystemConfig.js';

/**
 * `src/app.ts` mounts dynamicSlowDown and dynamicRateLimit only when NODE_ENV is not
 * "test", and tests/setup/env.ts sets exactly that, so the rest of the suite runs with
 * both absent. tests/unit/middleware/rateLimit.spec.ts covers the modules but mocks
 * express-rate-limit and express-slow-down away, so nothing anywhere exercises the real
 * libraries as mounted middleware. That gap is #231.
 *
 * Each case below imports the app fresh under a development NODE_ENV to get them
 * mounted. /health/status is the probe: it needs no auth and touches no database, so a
 * response is the limiter's verdict and nothing else.
 */
async function loadAppWithLimiters() {
  vi.resetModules();
  vi.stubEnv('NODE_ENV', 'development');

  const { createApp } = await import('../../../src/app.js');
  return (await createApp()) as Application;
}

beforeEach(() => {
  vi.clearAllMocks();
  // delay_after well above anything these tests send: express-slow-down is mounted ahead
  // of the rate limiter and would otherwise sleep hits * 1000ms before it ever answers.
  (getSystemConfig as ReturnType<typeof vi.fn>).mockResolvedValue({
    rate_limit: 3,
    delay_after: 1000,
  });
});

afterEach(() => {
  vi.unstubAllEnvs();
  vi.resetModules();
});

describe('global rate limiting', () => {
  it('serves requests up to the configured limit', async () => {
    const app = await loadAppWithLimiters();

    for (let i = 0; i < 3; i++) {
      const res = await request(app).get('/health/status');
      expect(res.status).toBe(200);
    }
  });

  it('refuses the request past the configured limit', async () => {
    const app = await loadAppWithLimiters();

    for (let i = 0; i < 3; i++) {
      await request(app).get('/health/status');
    }

    const res = await request(app).get('/health/status');

    expect(res.status).toBe(429);
  });

  it('takes its limit from system config rather than a hardcoded default', async () => {
    (getSystemConfig as ReturnType<typeof vi.fn>).mockResolvedValue({
      rate_limit: 1,
      delay_after: 1000,
    });

    const app = await loadAppWithLimiters();

    expect((await request(app).get('/health/status')).status).toBe(200);
    expect((await request(app).get('/health/status')).status).toBe(429);
  });

  it('advertises the limit in RateLimit headers', async () => {
    const app = await loadAppWithLimiters();

    const res = await request(app).get('/health/status');

    expect(res.headers['ratelimit-limit']).toBe('3');
    expect(res.headers['ratelimit-remaining']).toBe('2');
  });

  it('skips both limiters when DISABLE_AUTH_RATE_LIMITS is set outside production', async () => {
    vi.stubEnv('DISABLE_AUTH_RATE_LIMITS', 'true');

    const app = await loadAppWithLimiters();

    for (let i = 0; i < 6; i++) {
      const res = await request(app).get('/health/status');
      expect(res.status).toBe(200);
    }
  });

  /**
   * Pins what a throttled caller actually receives, which is not the JSON error shape
   * every other response on this API uses: the limiters are configured with a plain
   * string `message`, so express-rate-limit sends it as text. Asserted rather than
   * corrected because changing it is a contract change for the SDKs, and one of them has
   * already been bitten by it (seamless-auth-react#41, a non-JSON 429 crashing the
   * client). Change this test deliberately, with that coordination, not in passing.
   */
  it('answers with a plain-text body rather than the JSON error shape', async () => {
    const app = await loadAppWithLimiters();

    for (let i = 0; i < 3; i++) {
      await request(app).get('/health/status');
    }

    const res = await request(app).get('/health/status');

    expect(res.status).toBe(429);
    expect(res.headers['content-type']).not.toContain('application/json');
    expect(res.text).toBe('Too many requests, please try again later');
  });
});
