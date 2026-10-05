import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.unmock('../../../src/utils/otp.js');
vi.mock('../../../src/services/messagingService.js', () => ({
  sendOTPEmail: vi.fn(),
  sendOTPSMS: vi.fn(),
}));

import {
  generateRandomEmailOTP,
  generateRandomPhoneOTP,
  generateEmailOTP,
  generatePhoneOTP,
  hashOtpToken,
  verifyPhoneOTP,
  verifyEmailOTP,
} from '../../../src/utils/otp.js';

import { sendOTPEmail, sendOTPSMS } from '../../../src/services/messagingService';
function buildUser(overrides: any = {}) {
  return {
    email: 'test@example.com',
    phone: '+14155552671',

    emailVerificationToken: null,
    emailVerificationTokenExpiry: null,
    phoneVerificationToken: null,
    phoneVerificationTokenExpiry: null,

    emailVerified: false,
    phoneVerified: false,
    verified: false,

    update: vi.fn().mockResolvedValue(undefined),
    save: vi.fn().mockResolvedValue(undefined),

    ...overrides,
  };
}

describe('OTP utils', () => {
  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();
  });

  describe('generateRandomEmailOTP', () => {
    it('returns 6 uppercase letters', () => {
      const otp = generateRandomEmailOTP();

      expect(otp).toHaveLength(6);
      expect(/^[A-Z]{6}$/.test(otp)).toBe(true);
    });
  });

  describe('generateRandomPhoneOTP', () => {
    it('returns 6 digit number', () => {
      const otp = generateRandomPhoneOTP();

      expect(otp).toBeGreaterThanOrEqual(100000);
      expect(otp).toBeLessThanOrEqual(999999);
    });
  });

  // ---------------------------
  // Generate OTP
  // ---------------------------
  describe('generateEmailOTP', () => {
    it('updates user and sends email', async () => {
      const user = buildUser();

      const token = await generateEmailOTP(user as any);

      expect(user.update).toHaveBeenCalled();
      expect(user.update).toHaveBeenCalledWith(
        expect.objectContaining({
          emailVerificationToken: hashOtpToken(token),
          emailVerificationTokenExpiry: expect.any(Number),
        }),
      );
      expect(sendOTPEmail).toHaveBeenCalled();
    });

    it('throws if user missing', async () => {
      await expect(generateEmailOTP(null as any)).rejects.toThrow();
    });

    it('throws on update failure', async () => {
      const user = buildUser({
        update: vi.fn().mockRejectedValue(new Error('fail')),
      });

      await expect(generateEmailOTP(user as any)).rejects.toThrow();
    });

    it('issues the configured code to a review account, which then verifies', async () => {
      process.env.REVIEW_ACCOUNT_EMAILS = 'test@example.com';
      process.env.REVIEW_ACCOUNT_CODE = 'REVUEW';
      try {
        const user = buildUser();

        const token = await generateEmailOTP(user as any);

        expect(token).toBe('REVUEW');
        expect(user.update).toHaveBeenCalledWith(
          expect.objectContaining({ emailVerificationToken: hashOtpToken('REVUEW') }),
        );
        expect(sendOTPEmail).toHaveBeenCalledWith('test@example.com', 'REVUEW');

        const issued = user.update.mock.calls[0][0];
        const result = await verifyEmailOTP(buildUser({ ...issued }) as any, 'revuew');
        expect(result.verified).toBe(true);
      } finally {
        delete process.env.REVIEW_ACCOUNT_EMAILS;
        delete process.env.REVIEW_ACCOUNT_CODE;
      }
    });
  });

  describe('generatePhoneOTP', () => {
    it('updates user and sends sms', async () => {
      const user = buildUser();

      const token = await generatePhoneOTP(user as any);

      expect(user.update).toHaveBeenCalled();
      expect(user.update).toHaveBeenCalledWith(
        expect.objectContaining({
          phoneVerificationToken: hashOtpToken(String(token)),
          phoneVerificationTokenExpiry: expect.any(Number),
        }),
      );
      expect(sendOTPSMS).toHaveBeenCalled();
    });

    it('throws if user missing', async () => {
      await expect(generatePhoneOTP(null as any)).rejects.toThrow();
    });

    it('throws when the user has no registered phone number', async () => {
      const user = buildUser({ phone: null });

      await expect(generatePhoneOTP(user as any)).rejects.toThrow(
        'without a registered phone number',
      );
    });

    it('throws when persisting the generated phone OTP fails', async () => {
      const user = buildUser({
        update: vi.fn().mockRejectedValue(new Error('db down')),
      });

      await expect(generatePhoneOTP(user as any)).rejects.toThrow('Failed to set user OTP');
    });
  });

  // ---------------------------
  // Verify Phone OTP
  // ---------------------------
  describe('verifyPhoneOTP', () => {
    it('verifies valid OTP', async () => {
      const user = buildUser({
        phoneVerificationToken: hashOtpToken('123456'),
        phoneVerificationTokenExpiry: Date.now() + 10000,
        emailVerified: true,
      });

      const result = await verifyPhoneOTP(user as any, '123456');

      expect(result.verified).toBe(true);
      expect(user.phoneVerified).toBe(true);
      expect(user.verified).toBe(true);
      expect(user.save).toHaveBeenCalled();
    });

    it('returns false for invalid token', async () => {
      const user = buildUser({
        phoneVerificationToken: hashOtpToken('123456'),
        phoneVerificationTokenExpiry: Date.now() + 10000,
      });

      const result = await verifyPhoneOTP(user as any, 'wrong');

      expect(result.verified).toBe(false);
    });

    it('records the attempt that verified the phone', async () => {
      const user = buildUser({
        phoneVerificationToken: hashOtpToken('123456'),
        phoneVerificationTokenExpiry: Date.now() + 10000,
      });

      await verifyPhoneOTP(user as any, '123456', 'attempt-a');

      expect(user.phoneVerified).toBe(true);
      expect(user.phoneVerifiedAttemptId).toBe('attempt-a');
    });

    it('returns false for expired token', async () => {
      const user = buildUser({
        phoneVerificationToken: hashOtpToken('123456'),
        phoneVerificationTokenExpiry: Date.now() - 1000,
      });

      const result = await verifyPhoneOTP(user as any, '123456');

      expect(result.verified).toBe(false);
    });

    it('throws if missing data', async () => {
      const user = buildUser();

      await expect(verifyPhoneOTP(user as any, '123')).rejects.toThrow();
    });
  });

  // ---------------------------
  // Verify Email OTP
  // ---------------------------
  describe('verifyEmailOTP', () => {
    it('verifies valid OTP (case insensitive)', async () => {
      const user = buildUser({
        emailVerificationToken: hashOtpToken('ABCDEF'),
        emailVerificationTokenExpiry: Date.now() + 10000,
        phone: null,
      });

      const result = await verifyEmailOTP(user as any, 'abcdef');

      expect(result.verified).toBe(true);
      expect(user.emailVerified).toBe(true);
      expect(user.verified).toBe(true);
      expect(user.save).toHaveBeenCalled();
    });

    it('returns false for invalid token', async () => {
      const user = buildUser({
        emailVerificationToken: hashOtpToken('ABCDEF'),
        emailVerificationTokenExpiry: Date.now() + 10000,
      });

      const result = await verifyEmailOTP(user as any, 'wrong');

      expect(result.verified).toBe(false);
    });

    it('throws if missing data', async () => {
      const user = buildUser();

      await expect(verifyEmailOTP(user as any, '123')).rejects.toThrow();
    });

    describe('a phone verified before the address was proven', () => {
      // Anyone can start a registration for an address and verify their own phone on
      // the account it creates. Only the attempt that verified the phone keeps it.
      const pending = (overrides: any = {}) =>
        buildUser({
          emailVerificationToken: hashOtpToken('ABCDEF'),
          emailVerificationTokenExpiry: Date.now() + 10000,
          phoneVerified: true,
          phoneVerifiedAttemptId: 'attempt-a',
          ...overrides,
        });

      it('is kept when the same attempt verifies the email (phone-first sign up)', async () => {
        const user = pending();

        await verifyEmailOTP(user as any, 'abcdef', 'attempt-a');

        expect(user.verified).toBe(true);
        expect(user.phone).toBe('+14155552671');
        expect(user.phoneVerified).toBe(true);
        expect(user.phoneVerifiedAttemptId).toBeNull();
      });

      it('is removed when a different attempt verifies the email', async () => {
        const user = pending();

        await verifyEmailOTP(user as any, 'abcdef', 'attempt-b');

        expect(user.verified).toBe(true);
        expect(user.phone).toBeNull();
        expect(user.phoneVerified).toBe(false);
        expect(user.phoneVerifiedAttemptId).toBeNull();
      });

      it('is removed when the attempt is unknown', async () => {
        const user = pending();

        await verifyEmailOTP(user as any, 'abcdef');

        expect(user.phone).toBeNull();
        expect(user.phoneVerified).toBe(false);
      });

      it('is left alone once the account is already verified', async () => {
        const user = pending({ verified: true, emailVerified: true });

        await verifyEmailOTP(user as any, 'abcdef', 'attempt-b');

        expect(user.phone).toBe('+14155552671');
        expect(user.phoneVerified).toBe(true);
      });
    });
  });
});
it('rejects legacy plaintext phone OTP values (hashed-only after hardening)', async () => {
  const user = buildUser({
    phoneVerificationToken: '123456',
    phoneVerificationTokenExpiry: Date.now() + 10000,
    emailVerified: true,
  });

  const result = await verifyPhoneOTP(user as any, '123456');

  expect(result.verified).toBe(false);
});

it('rejects legacy plaintext email OTP values (hashed-only after hardening)', async () => {
  const user = buildUser({
    emailVerificationToken: 'ABCDEF',
    emailVerificationTokenExpiry: Date.now() + 10000,
    phone: null,
  });

  const result = await verifyEmailOTP(user as any, 'abcdef');

  expect(result.verified).toBe(false);
});

describe('OTP regression — hardened behavior', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('email OTP round-trips: a generated token verifies against the stored hash', async () => {
    const issuingUser = buildUser();
    const token = await generateEmailOTP(issuingUser as any, { sendMessage: false });
    const stored = (issuingUser.update as any).mock.calls[0][0].emailVerificationToken;

    const verifyingUser = buildUser({
      emailVerificationToken: stored,
      emailVerificationTokenExpiry: Date.now() + 100000,
    });

    expect((await verifyEmailOTP(verifyingUser as any, token)).verified).toBe(true);
  });

  it('email OTP round-trip is case-insensitive', async () => {
    const issuingUser = buildUser();
    const token = await generateEmailOTP(issuingUser as any, { sendMessage: false });
    const stored = (issuingUser.update as any).mock.calls[0][0].emailVerificationToken;

    const verifyingUser = buildUser({
      emailVerificationToken: stored,
      emailVerificationTokenExpiry: Date.now() + 100000,
    });

    expect((await verifyEmailOTP(verifyingUser as any, token.toLowerCase())).verified).toBe(true);
  });

  it('phone OTP round-trips: a generated token verifies against the stored hash', async () => {
    const issuingUser = buildUser();
    const token = await generatePhoneOTP(issuingUser as any, { sendMessage: false });
    const stored = (issuingUser.update as any).mock.calls[0][0].phoneVerificationToken;

    const verifyingUser = buildUser({
      phoneVerificationToken: stored,
      phoneVerificationTokenExpiry: Date.now() + 100000,
    });

    expect((await verifyPhoneOTP(verifyingUser as any, String(token))).verified).toBe(true);
  });

  it('stores OTPs hashed at rest (sha256: prefix, never the plaintext code)', async () => {
    const user = buildUser();
    const token = await generateEmailOTP(user as any, { sendMessage: false });
    const stored = (user.update as any).mock.calls[0][0].emailVerificationToken;

    expect(stored).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(stored).not.toContain(token);
  });
});

describe('OTP verification save failures', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('throws when persisting a verified phone OTP fails', async () => {
    const user = buildUser({
      phoneVerificationToken: hashOtpToken('123456'),
      phoneVerificationTokenExpiry: Date.now() + 10000,
      emailVerified: true,
      save: vi.fn().mockRejectedValue(new Error('db down')),
    });

    await expect(verifyPhoneOTP(user as any, '123456')).rejects.toThrow(
      'Failed to update user verification via phone OTP',
    );
    expect(user.save).toHaveBeenCalled();
  });

  it('throws when persisting a verified email OTP fails', async () => {
    const user = buildUser({
      emailVerificationToken: hashOtpToken('ABCDEF'),
      emailVerificationTokenExpiry: Date.now() + 10000,
      phone: null,
      save: vi.fn().mockRejectedValue(new Error('db down')),
    });

    await expect(verifyEmailOTP(user as any, 'abcdef')).rejects.toThrow(
      'Failed to update user verification via email OTP',
    );
    expect(user.save).toHaveBeenCalled();
  });

  it('leaves an already-verified user verified after email OTP', async () => {
    const user = buildUser({
      emailVerificationToken: hashOtpToken('ABCDEF'),
      emailVerificationTokenExpiry: Date.now() + 10000,
      phone: null,
      verified: true,
    });

    const result = await verifyEmailOTP(user as any, 'abcdef');

    expect(result.verified).toBe(true);
    expect(user.verified).toBe(true);
  });
});
