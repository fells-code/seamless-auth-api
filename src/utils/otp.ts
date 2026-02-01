/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import { User } from '../models/users';
import { sendOTPEmail, sendOTPSMS } from '../services/messagingService';
import getLogger from './logger';

const logger = getLogger('utils.otp');

export const generateRandomEmailOTP = (): string => {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  let result = '';
  for (let i = 0; i < 6; i++) {
    result += characters.charAt(Math.floor(Math.random() * characters.length));
  }
  return result;
};

export const generateRandomPhoneOTP = (): number => {
  return Math.floor(Math.random() * 900000) + 100000;
};

export const generateEmailOTP = async (user: User) => {
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
      emailVerificationToken: emailToken,
      emailVerificationTokenExpiry,
    });

    sendOTPEmail(user.email, emailToken);
  } catch (error) {
    logger.error(`Error generate email OTP: ${error}`);
    throw new Error('Failed to set user OTP');
  }
};

export const generatePhoneOTP = async (user: User) => {
  if (!user) {
    throw new Error('Cannot generate phone OTP for non-exsistent user');
  }

  try {
    // Set the token and the expiry time (ALWAYS 5 mins)
    const now = new Date();
    now.setMinutes(now.getMinutes() + 5);

    const phoneToken = generateRandomPhoneOTP();
    const phoneVerificationTokenExpiry = now.getTime();

    await user.update({
      phoneVerificationToken: String(phoneToken),
      phoneVerificationTokenExpiry,
    });

    sendOTPSMS(user.phone, phoneToken);
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
    user.phoneVerificationToken === verificationToken &&
    user.phoneVerificationTokenExpiry > new Date().getTime()
  ) {
    user.phoneVerified = true;
    user.phoneVerificationToken = null;
    user.phoneVerificationTokenExpiry = null;

    if (user.phoneVerified && user.emailVerified && !user.verified) {
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
    user.emailVerificationToken.toUpperCase() === verificationToken.toUpperCase() &&
    user.emailVerificationTokenExpiry > new Date().getTime()
  ) {
    user.emailVerified = true;
    user.emailVerificationToken = null;
    user.emailVerificationTokenExpiry = null;

    if (user.phoneVerified && user.emailVerified && !user.verified) {
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
