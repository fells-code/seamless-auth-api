import { describe, expect, it, vi } from 'vitest';

import { getSystemConfig } from '../../../src/config/getSystemConfig.js';
import {
  getLoginPolicy,
  normalizeLoginPolicy,
  resolveAvailableLoginMethods,
} from '../../../src/services/loginPolicyService.js';
import { buildSystemConfig } from '../../factories/systemConfigFactory.js';

describe('loginPolicyService', () => {
  it('reads and normalizes the persisted system config', async () => {
    (getSystemConfig as any).mockResolvedValue(
      buildSystemConfig({
        login_methods: ['email_otp', 'passkey'],
        passkey_login_fallback_enabled: false,
      }),
    );

    await expect(getLoginPolicy()).resolves.toEqual({
      loginMethods: ['passkey', 'email_otp'],
      passkeyFallbackEnabled: false,
    });

    vi.clearAllMocks();
  });

  it('uses passkey plus magic-link fallback defaults', () => {
    expect(normalizeLoginPolicy(null)).toEqual({
      loginMethods: ['passkey', 'magic_link'],
      passkeyFallbackEnabled: true,
    });
  });

  it('drops unrecognized login methods and defaults when none remain valid', () => {
    expect(
      normalizeLoginPolicy({
        login_methods: ['passkey', 'not-a-method'],
        passkey_login_fallback_enabled: true,
      }).loginMethods,
    ).toEqual(['passkey']);

    expect(
      normalizeLoginPolicy({
        login_methods: ['not-a-method', 'also-bogus'],
      }).loginMethods,
    ).toEqual(['passkey', 'magic_link']);
  });

  it('filters available methods by policy and user contact fields', () => {
    const policy = normalizeLoginPolicy({
      login_methods: ['passkey', 'magic_link', 'email_otp', 'phone_otp'],
      passkey_login_fallback_enabled: true,
    });

    expect(
      resolveAvailableLoginMethods({
        policy,
        user: { email: 'test@example.com', phone: null },
        hasPasskeyCredential: true,
        passkeyAvailable: true,
      }),
    ).toEqual(['passkey', 'magic_link', 'email_otp']);
  });

  it('returns passkey only when fallback is disabled and passkey is usable', () => {
    const policy = normalizeLoginPolicy({
      login_methods: ['passkey', 'magic_link', 'email_otp', 'phone_otp'],
      passkey_login_fallback_enabled: false,
    });

    expect(
      resolveAvailableLoginMethods({
        policy,
        user: { email: 'test@example.com', phone: '+14155552671' },
        hasPasskeyCredential: true,
        passkeyAvailable: true,
      }),
    ).toEqual(['passkey']);
  });

  it('never advertises oauth as a resolvable login method', () => {
    const policy = normalizeLoginPolicy({
      login_methods: ['magic_link', 'email_otp', 'oauth'],
      passkey_login_fallback_enabled: true,
    });

    expect(policy.loginMethods).toContain('oauth');

    const available = resolveAvailableLoginMethods({
      policy,
      user: { email: 'test@example.com', phone: '+14155552671' },
      hasPasskeyCredential: false,
      passkeyAvailable: true,
    });

    expect(available).toEqual(['magic_link', 'email_otp']);
    expect(available).not.toContain('oauth');
  });

  it('allows configured fallback methods when passkey is unavailable on the client', () => {
    const policy = normalizeLoginPolicy({
      login_methods: ['passkey', 'magic_link', 'phone_otp'],
      passkey_login_fallback_enabled: false,
    });

    expect(
      resolveAvailableLoginMethods({
        policy,
        user: { email: 'test@example.com', phone: '+14155552671' },
        hasPasskeyCredential: true,
        passkeyAvailable: false,
      }),
    ).toEqual(['magic_link', 'phone_otp']);
  });
});
