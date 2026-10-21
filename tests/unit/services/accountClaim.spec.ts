import { describe, expect, it } from 'vitest';

import { claimUnverifiedAccount } from '../../../src/services/accountClaim.js';

function user(overrides: Record<string, unknown> = {}) {
  return {
    verified: false,
    emailVerified: false,
    emailVerificationToken: 'hash',
    emailVerificationTokenExpiry: 1,
    phone: '+15550100',
    phoneVerified: true,
    phoneVerificationToken: null,
    phoneVerificationTokenExpiry: null,
    phoneVerifiedAttemptId: 'attempt-a',
    ...overrides,
  } as never as Parameters<typeof claimUnverifiedAccount>[0];
}

describe('claimUnverifiedAccount', () => {
  it('verifies the account and its email', () => {
    const account = user();

    expect(claimUnverifiedAccount(account, 'attempt-a')).toBe(true);
    expect(account).toEqual(
      expect.objectContaining({
        verified: true,
        emailVerified: true,
        emailVerificationToken: null,
        emailVerificationTokenExpiry: null,
        phoneVerifiedAttemptId: null,
      }),
    );
  });

  it('keeps a phone the claiming attempt verified', () => {
    const account = user();

    claimUnverifiedAccount(account, 'attempt-a');

    expect(account).toEqual(expect.objectContaining({ phone: '+15550100', phoneVerified: true }));
  });

  it.each([['attempt-b'], [undefined]])(
    'drops a phone verified by another attempt (%s)',
    (attempt) => {
      const account = user({ phoneVerificationToken: 'pending', phoneVerificationTokenExpiry: 2 });

      claimUnverifiedAccount(account, attempt);

      expect(account).toEqual(
        expect.objectContaining({
          phone: null,
          phoneVerified: false,
          phoneVerificationToken: null,
          phoneVerificationTokenExpiry: null,
        }),
      );
    },
  );

  it('does nothing to a verified account', () => {
    const account = user({ verified: true, emailVerified: true });

    expect(claimUnverifiedAccount(account, 'attempt-b')).toBe(false);
    expect(account).toEqual(expect.objectContaining({ phone: '+15550100', phoneVerified: true }));
  });
});
