import { describe, expect, it } from 'vitest';

import {
  normalizeLoginPolicy,
  resolveAvailableLoginMethods,
} from '../../../src/services/loginPolicyService.js';

describe('loginPolicyService', () => {
  it('uses passkey plus magic-link fallback defaults', () => {
    expect(normalizeLoginPolicy(null)).toEqual({
      loginMethods: ['passkey', 'magic_link'],
      passkeyFallbackEnabled: true,
    });
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
