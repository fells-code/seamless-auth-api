import { describe, expect, it, vi } from 'vitest';

import { getSystemConfig } from '../../../src/config/getSystemConfig.js';
import { Credential } from '../../../src/models/credentials.js';
import {
  getLoginPolicy,
  isPasskeyRequired,
  isPasskeyRequiredForUser,
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
      phishingResistantOnly: false,
    });

    vi.clearAllMocks();
  });

  it('uses passkey plus magic-link fallback defaults', () => {
    expect(normalizeLoginPolicy(null)).toEqual({
      loginMethods: ['passkey', 'magic_link'],
      passkeyFallbackEnabled: true,
      phishingResistantOnly: false,
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
      passkey_login_fallback_enabled: true,
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

  describe('passkey-only policy', () => {
    const passkeyOnly = () =>
      normalizeLoginPolicy({
        login_methods: ['passkey', 'magic_link', 'phone_otp'],
        passkey_login_fallback_enabled: false,
      });

    it('ignores a client claiming it cannot use a passkey', () => {
      expect(
        resolveAvailableLoginMethods({
          policy: passkeyOnly(),
          user: { email: 'test@example.com', phone: '+14155552671' },
          hasPasskeyCredential: true,
          passkeyAvailable: false,
        }),
      ).toEqual(['passkey']);
    });

    it('offers passkey only when the client says it can use one', () => {
      expect(
        resolveAvailableLoginMethods({
          policy: passkeyOnly(),
          user: { email: 'test@example.com', phone: '+14155552671' },
          hasPasskeyCredential: true,
          passkeyAvailable: true,
        }),
      ).toEqual(['passkey']);
    });

    it('offers passkey only when the client says nothing at all', () => {
      expect(
        resolveAvailableLoginMethods({
          policy: passkeyOnly(),
          user: { email: 'test@example.com', phone: '+14155552671' },
          hasPasskeyCredential: true,
        }),
      ).toEqual(['passkey']);
    });

    // The policy binds an account that can actually use a passkey. Without a
    // credential there is nothing to enforce, so the configured methods stand.
    it('still offers fallback methods to a user with no passkey', () => {
      expect(
        resolveAvailableLoginMethods({
          policy: passkeyOnly(),
          user: { email: 'test@example.com', phone: '+14155552671' },
          hasPasskeyCredential: false,
          passkeyAvailable: false,
        }),
      ).toEqual(['magic_link', 'phone_otp']);
    });

    it('does not enforce passkey when the deployment has not enabled it', () => {
      expect(
        resolveAvailableLoginMethods({
          policy: normalizeLoginPolicy({
            login_methods: ['magic_link', 'phone_otp'],
            passkey_login_fallback_enabled: false,
          }),
          user: { email: 'test@example.com', phone: '+14155552671' },
          hasPasskeyCredential: true,
          passkeyAvailable: false,
        }),
      ).toEqual(['magic_link', 'phone_otp']);
    });
  });

  describe('phishing-resistant-only mode', () => {
    it('narrows sign-in to passkeys whatever the method list and fallback say', () => {
      expect(
        normalizeLoginPolicy({
          login_methods: ['passkey', 'magic_link', 'email_otp', 'phone_otp', 'oauth'],
          passkey_login_fallback_enabled: true,
          phishing_resistant_only: true,
        }),
      ).toEqual({
        loginMethods: ['passkey'],
        passkeyFallbackEnabled: false,
        phishingResistantOnly: true,
      });
    });

    it('only turns on for a literal true', () => {
      expect(normalizeLoginPolicy({ phishing_resistant_only: 'true' }).phishingResistantOnly).toBe(
        false,
      );
      expect(normalizeLoginPolicy({ phishing_resistant_only: 1 }).phishingResistantOnly).toBe(
        false,
      );
    });

    it('offers no fallback to an account without a passkey', () => {
      const policy = normalizeLoginPolicy({
        login_methods: ['passkey', 'magic_link'],
        phishing_resistant_only: true,
      });

      expect(
        resolveAvailableLoginMethods({
          policy,
          user: { email: 'a@example.com', phone: '+15555555555' },
          hasPasskeyCredential: false,
        }),
      ).toEqual([]);
    });
  });

  describe('isPasskeyRequired', () => {
    const fallbackOff = normalizeLoginPolicy({
      login_methods: ['passkey', 'email_otp'],
      passkey_login_fallback_enabled: false,
    });
    const fallbackOn = normalizeLoginPolicy({
      login_methods: ['passkey', 'email_otp'],
      passkey_login_fallback_enabled: true,
    });

    it('requires a passkey of everyone in phishing-resistant-only mode', () => {
      const strict = normalizeLoginPolicy({ phishing_resistant_only: true });

      expect(isPasskeyRequired(strict, false)).toBe(true);
      expect(isPasskeyRequired(strict, true)).toBe(true);
    });

    it('requires one of a passkey holder when fallback is off', () => {
      expect(isPasskeyRequired(fallbackOff, true)).toBe(true);
      expect(isPasskeyRequired(fallbackOff, false)).toBe(false);
    });

    it('requires nothing when fallback is on', () => {
      expect(isPasskeyRequired(fallbackOn, true)).toBe(false);
    });

    it('requires nothing when passkeys are not a sign-in method at all', () => {
      const noPasskeys = normalizeLoginPolicy({
        login_methods: ['email_otp'],
        passkey_login_fallback_enabled: false,
      });

      expect(isPasskeyRequired(noPasskeys, true)).toBe(false);
    });

    it('looks the account up only when the answer depends on it', async () => {
      (Credential.count as any).mockResolvedValue(1);

      await expect(
        isPasskeyRequiredForUser('user-1', normalizeLoginPolicy({ phishing_resistant_only: true })),
      ).resolves.toBe(true);
      await expect(isPasskeyRequiredForUser('user-1', fallbackOn)).resolves.toBe(false);
      expect(Credential.count).not.toHaveBeenCalled();

      await expect(isPasskeyRequiredForUser('user-1', fallbackOff)).resolves.toBe(true);
      expect(Credential.count).toHaveBeenCalledWith({ where: { userId: 'user-1' } });

      (Credential.count as any).mockResolvedValue(0);
      await expect(isPasskeyRequiredForUser('user-1', fallbackOff)).resolves.toBe(false);

      vi.clearAllMocks();
    });
  });
});
