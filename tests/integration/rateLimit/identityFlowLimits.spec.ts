import express, { Application, NextFunction, Request, Response } from 'express';
import request from 'supertest';
import { beforeEach, describe, expect, it, vi } from 'vitest';

// tests/setup/mocks.ts replaces the limiters with pass-throughs for the whole suite.
vi.unmock('../../../src/middleware/rateLimit');

import { getSystemConfig } from '../../../src/config/getSystemConfig.js';

type IdentityLimiter = (req: Request, res: Response, next: NextFunction) => unknown;

/**
 * Mounts one identity limiter behind a stand-in for bearer auth, which is what sets the
 * user and the attempt on a real ephemeral route before route middleware runs.
 */
async function appWith(name: 'otpIdentityLimiter' | 'magicLinkEmailLimiter') {
  vi.resetModules();
  const limiters = await import('../../../src/middleware/rateLimit.js');
  const limiter = limiters[name] as IdentityLimiter;
  const app = express();

  app.post(
    '/flow',
    (req, _res, next) => {
      Object.assign(req, { user: { email: req.get('x-test-email'), phone: null } });
      const attempt = req.get('x-test-attempt');
      if (attempt) Object.assign(req, { attemptId: attempt });
      next();
    },
    limiter,
    (_req, res) => {
      res.status(200).json({ ok: true });
    },
  );

  return app as Application;
}

function send(app: Application, email: string, attempt?: string) {
  const call = request(app).post('/flow').set('x-test-email', email);
  return attempt ? call.set('x-test-attempt', attempt) : call;
}

async function status(app: Application, email: string, attempt?: string) {
  return (await send(app, email, attempt)).status;
}

beforeEach(() => {
  vi.clearAllMocks();
  (getSystemConfig as ReturnType<typeof vi.fn>).mockResolvedValue({});
});

describe.each(['otpIdentityLimiter', 'magicLinkEmailLimiter'] as const)('%s', (name) => {
  it('refuses an attempt past perIdentity', async () => {
    const app = await appWith(name);

    for (let i = 0; i < 5; i++) {
      expect(await status(app, 'owner@example.com', 'attempt-a')).toBe(200);
    }

    expect(await status(app, 'owner@example.com', 'attempt-a')).toBe(429);
  });

  it('leaves another attempt for the same address its own allowance', async () => {
    const app = await appWith(name);

    for (let i = 0; i < 6; i++) {
      await send(app, 'owner@example.com', 'stranger');
    }

    expect(await status(app, 'owner@example.com', 'owner')).toBe(200);
  });

  it('caps every attempt for one address together at four times perIdentity', async () => {
    const app = await appWith(name);

    for (let attempt = 0; attempt < 4; attempt++) {
      for (let i = 0; i < 5; i++) {
        expect(await status(app, 'owner@example.com', `attempt-${attempt}`)).toBe(200);
      }
    }

    expect(await status(app, 'owner@example.com', 'attempt-new')).toBe(429);
    expect(await status(app, 'other@example.com', 'attempt-new')).toBe(200);
  });

  it('reads perIdentity from flow_rate_limits', async () => {
    (getSystemConfig as ReturnType<typeof vi.fn>).mockResolvedValue({
      flow_rate_limits: {
        windowSeconds: 900,
        otp: { perIp: 10, perIdentity: 1 },
        magicLink: { perIp: 20, perIdentity: 1 },
        oauth: { perIp: 30, perProvider: 10 },
      },
    });
    const app = await appWith(name);

    expect(await status(app, 'owner@example.com', 'a')).toBe(200);
    expect(await status(app, 'owner@example.com', 'a')).toBe(429);
    for (const attempt of ['b', 'c', 'd']) {
      expect(await status(app, 'owner@example.com', attempt)).toBe(200);
    }
    expect(await status(app, 'owner@example.com', 'e')).toBe(429);
  });

  it('scopes a request without an attempt to the requester address', async () => {
    const app = await appWith(name);

    for (let i = 0; i < 5; i++) {
      expect(await status(app, 'owner@example.com')).toBe(200);
    }

    expect(await status(app, 'owner@example.com')).toBe(429);
    expect(await status(app, 'owner@example.com', 'owner')).toBe(200);
  });
});
