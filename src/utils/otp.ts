/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { randomInt, timingSafeEqual } from 'crypto';

import { User } from '../models/users.js';
import { sendOTPEmail, sendOTPSMS } from '../services/messagingService.js';
import getLogger from './logger.js';
import { hashSha256 } from './utils.js';

const logger = getLogger('utils.otp');
const EMAIL_OTP_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const OTP_HASH_PREFIX = 'sha256:';

export interface GenerateOtpOptions {
  sendMessage?: boolean;
}

function safeStringEqual(left: string, right: string) {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);

  if (leftBuffer.length !== rightBuffer.length) {
    return false;
  }

  return timingSafeEqual(leftBuffer, rightBuffer);
}

function normalizeEmailOtp(token: string) {
  return token.trim().toUpperCase();
}

function normalizePhoneOtp(token: string) {
  return token.trim();
}

export function hashOtpToken(token: string) {
  return `${OTP_HASH_PREFIX}${hashSha256(token)}`;
}

function otpMatchesStoredValue(
  storedToken: string,
  verificationToken: string,
  normalize: (token: string) => string,
) {
  // OTPs are always stored hashed (`sha256:` prefix). Compare the hash of the
  // normalized submission against the stored hash in constant time. Plaintext OTPs
  // are no longer accepted; any issued before hashing (5-min TTL) simply expire.
  return safeStringEqual(storedToken, hashOtpToken(normalize(verificationToken)));
}

export const generateRandomEmailOTP = (): string => {
  let result = '';
  for (let i = 0; i < 6; i++) {
    result += EMAIL_OTP_ALPHABET.charAt(randomInt(EMAIL_OTP_ALPHABET.length));
  }
  return result;
};

export const generateRandomPhoneOTP = (): number => {
  return randomInt(100000, 1000000);
};

export const generateEmailOTP = async (
  user: User,
  options: GenerateOtpOptions = {},
): Promise<string> => {
  if (!user) {
    throw new Error('Cannot generate email OTP for non-exsistent user');
  }

  try {
    // Set the token and the expiry time (ALWAYS 5 mins)
    const now = new Date();
    now.setMinutes(now.getMinutes() + 5);

    const emailToken = generateRandomEmailOTP();
    const emailVerificationTokenExpiry = now.getTime();

    await user.update({
      emailVerificationToken: hashOtpToken(normalizeEmailOtp(emailToken)),
      emailVerificationTokenExpiry,
    });

    if (options.sendMessage !== false) {
      await sendOTPEmail(user.email, emailToken);
    }

    return emailToken;
  } catch (error) {
    logger.error(`Error generate email OTP: ${error}`);
    throw new Error('Failed to set user OTP');
  }
};

export const generatePhoneOTP = async (
  user: User,
  options: GenerateOtpOptions = {},
): Promise<number> => {
  if (!user) {
    throw new Error('Cannot generate phone OTP for non-exsistent user');
  }

  if (!user.phone) {
    throw new Error('Cannot generate phone OTP without a registered phone number');
  }

  try {
    // Set the token and the expiry time (ALWAYS 5 mins)
    const now = new Date();
    now.setMinutes(now.getMinutes() + 5);

    const phoneToken = generateRandomPhoneOTP();
    const phoneVerificationTokenExpiry = now.getTime();

    await user.update({
      phoneVerificationToken: hashOtpToken(String(phoneToken)),
      phoneVerificationTokenExpiry,
    });

    if (options.sendMessage !== false) {
      await sendOTPSMS(user.phone, phoneToken);
    }

    return phoneToken;
  } catch (error) {
    logger.error(`Error generate phone OTP: ${error}`);
    throw new Error('Failed to set user OTP');
  }
};

export const verifyPhoneOTP = async (
  user: User,
  verificationToken: string,
): Promise<{ user: User; verified: boolean }> => {
  if (!user || !user.phoneVerificationToken || !user.phoneVerificationTokenExpiry) {
    throw new Error('Cannot verify phone OTP due to incomplete user data');
  }

  if (
    otpMatchesStoredValue(user.phoneVerificationToken, verificationToken, normalizePhoneOtp) &&
    user.phoneVerificationTokenExpiry > new Date().getTime()
  ) {
    user.phoneVerified = true;
    user.phoneVerificationToken = null;
    user.phoneVerificationTokenExpiry = null;

    if (user.emailVerified && !user.verified) {
      user.verified = true;
    }

    try {
      await user.save();
    } catch (error) {
      logger.error(`Error verifying phone OTP: ${error}`);
      throw new Error('Failed to update user verfication via phone OTP');
    }
  } else {
    return { user, verified: false };
  }

  return { user, verified: true };
};

export const verifyEmailOTP = async (
  user: User,
  verificationToken: string,
): Promise<{ user: User; verified: boolean }> => {
  if (!user || !user.emailVerificationToken || !user.emailVerificationTokenExpiry) {
    throw new Error('Cannot verify phone OTP due to incomplete user data');
  }

  if (
    otpMatchesStoredValue(user.emailVerificationToken, verificationToken, normalizeEmailOtp) &&
    user.emailVerificationTokenExpiry > new Date().getTime()
  ) {
    user.emailVerified = true;
    user.emailVerificationToken = null;
    user.emailVerificationTokenExpiry = null;

    if (user.emailVerified && !user.verified) {
      user.verified = true;
    }

    try {
      await user.save();
    } catch (error) {
      logger.error(`Error verifying email OTP: ${error}`);
      throw new Error('Failed to update user verfication via phone OTP');
    }
  } else {
    return { user, verified: false };
  }

  return { user, verified: true };
};
