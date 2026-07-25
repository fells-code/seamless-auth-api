import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { rateLimitsDisabled } from '../../src/middleware/rateLimitsDisabled.js';

describe('rateLimitsDisabled', () => {
  const saved = {
    flag: process.env.DISABLE_AUTH_RATE_LIMITS,
    nodeEnv: process.env.NODE_ENV,
  };

  beforeEach(() => {
    delete process.env.DISABLE_AUTH_RATE_LIMITS;
    process.env.NODE_ENV = 'development';
  });

  afterEach(() => {
    if (saved.flag === undefined) delete process.env.DISABLE_AUTH_RATE_LIMITS;
    else process.env.DISABLE_AUTH_RATE_LIMITS = saved.flag;
    process.env.NODE_ENV = saved.nodeEnv;
  });

  it('is false by default (flag unset)', () => {
    expect(rateLimitsDisabled()).toBe(false);
  });

  it('is false when the flag is any value other than "true"', () => {
    process.env.DISABLE_AUTH_RATE_LIMITS = '1';
    expect(rateLimitsDisabled()).toBe(false);
    process.env.DISABLE_AUTH_RATE_LIMITS = 'yes';
    expect(rateLimitsDisabled()).toBe(false);
  });

  it('is true when the flag is "true" outside production', () => {
    process.env.DISABLE_AUTH_RATE_LIMITS = 'true';
    process.env.NODE_ENV = 'development';
    expect(rateLimitsDisabled()).toBe(true);
    process.env.NODE_ENV = 'test';
    expect(rateLimitsDisabled()).toBe(true);
  });

  it('is refused under production even when the flag is "true"', () => {
    process.env.DISABLE_AUTH_RATE_LIMITS = 'true';
    process.env.NODE_ENV = 'production';
    expect(rateLimitsDisabled()).toBe(false);
  });
});
