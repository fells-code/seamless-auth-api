import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { conformanceModeEnabled } from '../../../src/config/conformanceMode.js';

describe('conformanceModeEnabled', () => {
  const saved = {
    flag: process.env.FIDO_CONFORMANCE_MODE,
    nodeEnv: process.env.NODE_ENV,
  };

  beforeEach(() => {
    delete process.env.FIDO_CONFORMANCE_MODE;
    process.env.NODE_ENV = 'development';
  });

  afterEach(() => {
    if (saved.flag === undefined) delete process.env.FIDO_CONFORMANCE_MODE;
    else process.env.FIDO_CONFORMANCE_MODE = saved.flag;
    process.env.NODE_ENV = saved.nodeEnv;
  });

  it('is false by default (flag unset)', () => {
    expect(conformanceModeEnabled()).toBe(false);
  });

  it('is false when the flag is any value other than "true"', () => {
    process.env.FIDO_CONFORMANCE_MODE = '1';
    expect(conformanceModeEnabled()).toBe(false);
    process.env.FIDO_CONFORMANCE_MODE = 'yes';
    expect(conformanceModeEnabled()).toBe(false);
  });

  it('is true when the flag is "true" outside production', () => {
    process.env.FIDO_CONFORMANCE_MODE = 'true';
    process.env.NODE_ENV = 'development';
    expect(conformanceModeEnabled()).toBe(true);
    process.env.NODE_ENV = 'test';
    expect(conformanceModeEnabled()).toBe(true);
  });

  it('is refused under production even when the flag is "true"', () => {
    process.env.FIDO_CONFORMANCE_MODE = 'true';
    process.env.NODE_ENV = 'production';
    expect(conformanceModeEnabled()).toBe(false);
  });
});
