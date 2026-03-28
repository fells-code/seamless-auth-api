import { describe, expect, it, vi } from 'vitest';

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
  // ---------------------------
  // Random generators
  // ---------------------------
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

      await generateEmailOTP(user as any);

      expect(user.update).toHaveBeenCalled();
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
  });

  describe('generatePhoneOTP', () => {
    it('updates user and sends sms', async () => {
      const user = buildUser();

      await generatePhoneOTP(user as any);

      expect(user.update).toHaveBeenCalled();
      expect(sendOTPSMS).toHaveBeenCalled();
    });

    it('throws if user missing', async () => {
      await expect(generatePhoneOTP(null as any)).rejects.toThrow();
    });
  });

  // ---------------------------
  // Verify Phone OTP
  // ---------------------------
  describe('verifyPhoneOTP', () => {
    it('verifies valid OTP', async () => {
      const user = buildUser({
        phoneVerificationToken: '123456',
        phoneVerificationTokenExpiry: Date.now() + 10000,
      });

      const result = await verifyPhoneOTP(user as any, '123456');

      expect(result.verified).toBe(true);
      expect(user.phoneVerified).toBe(true);
      expect(user.save).toHaveBeenCalled();
    });

    it('returns false for invalid token', async () => {
      const user = buildUser({
        phoneVerificationToken: '123456',
        phoneVerificationTokenExpiry: Date.now() + 10000,
      });

      const result = await verifyPhoneOTP(user as any, 'wrong');

      expect(result.verified).toBe(false);
    });

    it('returns false for expired token', async () => {
      const user = buildUser({
        phoneVerificationToken: '123456',
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
        emailVerificationToken: 'ABCDEF',
        emailVerificationTokenExpiry: Date.now() + 10000,
      });

      const result = await verifyEmailOTP(user as any, 'abcdef');

      expect(result.verified).toBe(true);
      expect(user.emailVerified).toBe(true);
      expect(user.save).toHaveBeenCalled();
    });

    it('returns false for invalid token', async () => {
      const user = buildUser({
        emailVerificationToken: 'ABCDEF',
        emailVerificationTokenExpiry: Date.now() + 10000,
      });

      const result = await verifyEmailOTP(user as any, 'wrong');

      expect(result.verified).toBe(false);
    });

    it('throws if missing data', async () => {
      const user = buildUser();

      await expect(verifyEmailOTP(user as any, '123')).rejects.toThrow();
    });
  });
});
