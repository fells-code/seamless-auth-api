/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import { Request, Response } from 'express';

import { setAuthCookies } from '../lib/cookie';
import {
  generateRefreshToken,
  hashRefreshToken,
  signAccessToken,
  signEphemeralToken,
} from '../lib/token';
import { Session } from '../models/sessions';
import { AuthEventService } from '../services/authEventService';
import { AuthenticatedRequest } from '../types/types';
import getLogger from '../utils/logger';
import { generateEmailOTP, generatePhoneOTP, verifyEmailOTP, verifyPhoneOTP } from '../utils/otp';
import { computeSessionTimes, isValidEmail, isValidPhoneNumber } from '../utils/utils';

const logger = getLogger('otp');
const AUTH_MODE: 'web' | 'server' = process.env.AUTH_MODE! as 'web' | 'server';

export const sendPhoneOTP = async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const user = authReq.user;
  const phone = user.phone;

  if (!phone) {
    logger.warn(`Missing phone`);
    AuthEventService.log({
      userId: user.id,
      type: 'otp_suspicious',
      req,
      metadata: { reason: 'Missing required phone.' },
    });
    return res.status(400).json({ message: 'Invalid data' });
  }

  logger.info(`Sending OTP to phone number: ${phone}`);

  try {
    if (!isValidPhoneNumber(phone)) {
      logger.warn(`Invalid phone provided: ${phone}`);
      AuthEventService.log({
        userId: null,
        type: 'otp_suspicious',
        req,
        metadata: { reason: 'Invalid phone number.' },
      });
      return res.status(400).json({ message: 'Invalid data' });
    }

    if (!user) {
      logger.error(`Attempted to send OTP to an unknown user: ${phone}`);
      AuthEventService.log({
        userId: null,
        type: 'otp_suspicious',
        req,
        metadata: { reason: 'Missing required phone.' },
      });
      return res.status(400).json({ message: 'Invalid data' });
    }

    logger.info(`${phone} requested a phone OTP`);
    await generatePhoneOTP(user);

    AuthEventService.log({
      userId: null,
      type: 'otp_success',
      req,
    });

    const token = await signEphemeralToken(user.id);

    if (AUTH_MODE === 'web') {
      await setAuthCookies(res, { ephemeralToken: token });
      return res.status(200).json({ message: 'success' });
    }

    return res.status(200).json({ message: 'success', token });
  } catch (error: unknown) {
    if (error instanceof Error) {
      logger.error(`Error sending phone OTP ${error.message}`);
    } else {
      logger.error(`Error during registration: ${String(error)}`);
    }

    return res.status(500).json({ message: 'Internal server error' });
  }
};

export const sendEmailOTP = async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const user = authReq.user;
  const email = user.email;

  try {
    if (!user) {
      logger.warn(`Attempted to send OTP to an unknown user: ${email}`);
      AuthEventService.log({
        userId: null,
        type: 'otp_suspicious',
        req,
        metadata: { reason: 'Missing required user.' },
      });
      return res.status(400).json({ message: 'Invalid data.' });
    }

    if (!email) {
      logger.warn(`Missing email`);
      AuthEventService.log({
        userId: null,
        type: 'otp_suspicious',
        req,
        metadata: { reason: 'Missing required email.' },
      });
      return res.status(400).json({ message: 'Invalid data.' });
    }

    logger.info(`Sending OTP to email: ${email}`);

    if (!isValidEmail(email)) {
      logger.error(`Invalid email provided: ${email}`);
      AuthEventService.log({
        userId: null,
        type: 'otp_suspicious',
        req,
        metadata: { reason: 'Invalid email.' },
      });
      return res.status(400).json({ message: 'Invalid data.' });
    }

    logger.info(`${email} requested an email OTP`);
    await generateEmailOTP(user);
    AuthEventService.log({
      userId: null,
      type: 'otp_success',
      req,
    });

    const token = await signEphemeralToken(user.id);

    if (AUTH_MODE === 'web') {
      await setAuthCookies(res, { ephemeralToken: token });
      return res.status(200).json({ message: 'success' });
    }

    return res.status(200).json({ message: 'success', token });
  } catch (error: unknown) {
    if (error instanceof Error) {
      logger.error(`Error sending email OTP ${error.message}`);
    } else {
      logger.error(`Error during registration: ${String(error)}`);
    }

    return res.status(500).json({ message: 'Internal server error' });
  }
};

export const verifyPhoneNumber = async (req: Request, res: Response) => {
  const { verificationToken } = req.body;

  const authReq = req as AuthenticatedRequest;
  let user = authReq.user;
  const email = user.email;
  const phone = user.phone;

  logger.info(`Verifying phone number: ${phone}`);

  if (!user || !user.phoneVerificationTokenExpiry || !user.phoneVerificationToken) {
    logger.warn(`Failed to find a user for this phone verification token - ${verificationToken}`);
    await AuthEventService.log({
      userId: user.id,
      type: 'verify_otp_suspicious',
      req,
      metadata: { reason: 'Missing data' },
    });
    return res.status(401).json({ message: 'Failed to verify OTP' });
  }

  try {
    if (!verificationToken || !phone || !email) {
      logger.warn(`Missing data from verify phone numnber request.`);
      await AuthEventService.log({
        userId: user.id,
        type: 'verify_otp_suspicious',
        req,
        metadata: { reason: 'Missing data' },
      });
      return res.status(401).json({ message: 'Not Allowed.' });
    }

    const verificationResult = await verifyPhoneOTP(user, verificationToken);

    user = verificationResult.user;
    const verified = verificationResult.verified;

    if (verified) {
      logger.info(`${phone} verifed their phone number`);
      await AuthEventService.log({
        userId: user.id,
        type: 'verify_otp_success',
        req,
        metadata: { reason: 'User verified their phone number' },
      });
      let token, refreshToken, refreshTokenHash;

      if (user.phoneVerified && user.emailVerified && user.verified) {
        logger.info(`${phone} is fully verified. Logging in...`);
        await AuthEventService.log({
          userId: user.id,
          type: 'verify_otp_success',
          req,
          metadata: { reason: 'User completed verification of phone and email' },
        });

        refreshToken = generateRefreshToken();
        refreshTokenHash = await hashRefreshToken(refreshToken);
        const { expiresAt, idleExpiresAt } = computeSessionTimes();

        const session = await Session.create({
          userId: user.id,
          infraId: process.env.APP_ID!,
          mode: AUTH_MODE,
          refreshTokenHash,
          userAgent: req.get('user-agent'),
          ipAddress: req.ip,
          expiresAt,
          idleExpiresAt,
          lastUsedAt: undefined,
        });

        token = await signAccessToken(session.id, user.id);
      }

      if (token && refreshToken) {
        if (AUTH_MODE === 'web') {
          await setAuthCookies(res, { accessToken: token, refreshToken: refreshTokenHash });
          return res.status(200).json({ message: 'Success' });
        }

        return res.status(200).json({ message: 'Success', token, refreshTokenHash });
      }
      res.json({ message: 'Success' });
    } else {
      logger.warn(
        `Verfication tokens did not match ${verificationToken} vs ${
          user.phoneVerificationToken
        } or ${user.phoneVerificationTokenExpiry} is less than ${new Date().getTime()}`,
      );
      return res.status(401).json({ message: 'Not allowed' });
    }
  } catch (error) {
    logger.error(`Failed to verify OTP: ${error}`);
    return res.status(500).json({ message: 'Internal server error' });
  }
};

export const verifyEmail = async (req: Request, res: Response) => {
  const { verificationToken } = req.body;
  const authReq = req as AuthenticatedRequest;
  let user = authReq.user;
  const email = user.email;
  const phone = user.phone;

  logger.info(`Verifying email: ${email}`);

  if (!user || !user.emailVerificationTokenExpiry || !user.emailVerificationToken) {
    logger.warn(
      `Failed to find a user for this email verification token - ${verificationToken}:${email}:${phone}`,
    );
    await AuthEventService.log({
      userId: user.id,
      type: 'verify_otp_suspicious',
      req,
      metadata: { reason: 'Missing data' },
    });
    return res.status(401).json({ message: 'Invalid data.' });
  }

  if (!verificationToken) {
    logger.warn(`Missing verification token ${req.body}`);
    await AuthEventService.log({
      userId: user.id,
      type: 'verify_otp_suspicious',
      req,
      metadata: { reason: 'Missing data' },
    });
    return res.status(401).json({ message: 'Invalid data' });
  }

  if (!email || !phone) {
    logger.warn(`Missing email or phone`);
    await AuthEventService.log({
      userId: user.id,
      type: 'verify_otp_suspicious',
      req,
      metadata: { reason: 'Missing data' },
    });
    return res.status(401).json({ message: 'Invalid data' });
  }

  const verificationResult = await verifyEmailOTP(user, verificationToken);

  user = verificationResult.user;
  const verified = verificationResult.verified;

  if (verified) {
    logger.info(`${email} verifed their email`);
    await AuthEventService.log({
      userId: user.id,
      type: 'verify_otp_success',
      req,
      metadata: { reason: 'User verified their email number' },
    });
    let token, refreshToken, refreshTokenHash;

    if (user.phoneVerified && user.emailVerified && user.verified) {
      logger.info(`${email} is fully verified. Logging in...`);

      await AuthEventService.log({
        userId: user.id,
        type: 'verify_otp_success',
        req,
        metadata: { reason: 'User completed verification of phone and email' },
      });

      refreshToken = generateRefreshToken();
      refreshTokenHash = await hashRefreshToken(refreshToken);
      const { expiresAt, idleExpiresAt } = computeSessionTimes();

      const session = await Session.create({
        userId: user.id,
        infraId: process.env.APP_ID!,
        mode: AUTH_MODE,
        refreshTokenHash,
        userAgent: req.get('user-agent'),
        ipAddress: req.ip,
        expiresAt,
        idleExpiresAt,
        lastUsedAt: undefined,
      });

      token = await signAccessToken(session.id, user.id);
    }

    if (token && refreshToken) {
      if (AUTH_MODE === 'web') {
        await setAuthCookies(res, { accessToken: token, refreshToken: refreshTokenHash });
        return res.status(200).json({ message: 'Success' });
      }

      return res.status(200).json({ message: 'Success', token, refreshTokenHash });
    }
    return res.json({ message: 'Success' });
  } else {
    logger.error(
      `Verfication tokens did not match ${verificationToken} vs ${user.emailVerificationToken} or ${
        user.emailVerificationTokenExpiry
      } is less than ${new Date().getTime()}`,
    );
  }

  return res.status(500).json({ message: 'Internal server error' });
};

export const verifyLoginPhoneNumber = async (req: Request, res: Response) => {
  const { verificationToken } = req.body;
  const authReq = req as AuthenticatedRequest;
  let user = authReq.user;
  const email = user.email;
  const phone = user.phone;

  logger.info(`Verifying login phone number: ${phone}`);

  if (!user || !user.phoneVerificationTokenExpiry || !user.phoneVerificationToken) {
    logger.warn(`Failed to find a user for this phone verification token - ${verificationToken}`);
    await AuthEventService.log({
      userId: user.id,
      type: 'verify_otp_suspicious',
      req,
      metadata: { reason: 'Missing data' },
    });
    return res.status(401).json({ message: 'Not allowed' });
  }

  try {
    if (!verificationToken || !phone || !email) {
      logger.warn(`Missing data from verify phone numnber request.`);
      await AuthEventService.log({
        userId: user.id,
        type: 'verify_otp_suspicious',
        req,
        metadata: { reason: 'Missing data' },
      });
      return res.status(401).json({ message: 'Not Allowed.' });
    }

    const verificationResult = await verifyPhoneOTP(user, verificationToken);

    user = verificationResult.user;
    const verified = verificationResult.verified;

    if (verified) {
      logger.info(`${phone} is verified for login.`);
      await AuthEventService.log({
        userId: user.id,
        type: 'verify_otp_success',
        req,
      });

      let token, refreshToken, refreshTokenHash;

      if (user.phoneVerified && user.emailVerified && user.verified) {
        logger.info(`${email} is fully verified. Logging in...`);

        await AuthEventService.log({
          userId: user.id,
          type: 'verify_otp_success',
          req,
          metadata: { reason: 'User completed verification of phone and email' },
        });

        refreshToken = generateRefreshToken();
        refreshTokenHash = await hashRefreshToken(refreshToken);
        const { expiresAt, idleExpiresAt } = computeSessionTimes();

        const session = await Session.create({
          userId: user.id,
          infraId: process.env.APP_ID!,
          mode: AUTH_MODE,
          refreshTokenHash,
          userAgent: req.get('user-agent'),
          ipAddress: req.ip,
          expiresAt,
          idleExpiresAt,
          lastUsedAt: undefined,
        });

        token = await signAccessToken(session.id, user.id);
      }

      if (token && refreshToken) {
        try {
          await user.update({ lastLogin: new Date() });
        } catch (error) {
          logger.warn(`An error occured saving user last login - ${error}`);
        }
        if (AUTH_MODE === 'web') {
          await setAuthCookies(res, { accessToken: token, refreshToken: refreshTokenHash });
          return res.status(200).json({ message: 'Success' });
        }

        return res.status(200).json({ message: 'Success', token, refreshTokenHash });
      }
      return res.json({ message: 'Success' });
    } else {
      logger.warn(
        `Verfication tokens did not match ${verificationToken} vs ${
          user.phoneVerificationToken
        } or ${user.phoneVerificationTokenExpiry} is less than ${new Date().getTime()}`,
      );
      await AuthEventService.log({
        userId: user.id,
        type: 'verify_otp_failed',
        req,
        metadata: { reason: 'User verification failed for phone' },
      });
      return res.status(401).json({ message: 'Not allowed' });
    }
  } catch (error) {
    logger.error(`Failed to verify OTP: ${error}`);
    return res.status(500).json({ message: 'Internal server error' });
  }
};

export const verifyLoginEmail = async (req: Request, res: Response) => {
  const { verificationToken } = req.body;
  const authReq = req as AuthenticatedRequest;
  let user = authReq.user;
  const email = user.email;
  const phone = user.phone;

  logger.info(`Verifying login email: ${email}`);

  if (!user || !user.emailVerificationTokenExpiry || !user.emailVerificationToken) {
    logger.warn(
      `Failed to find a user for this email verification token - ${verificationToken}:${email}:${phone}`,
    );
    await AuthEventService.log({
      userId: user.id,
      type: 'verify_otp_suspicious',
      req,
      metadata: { reason: 'Missing data' },
    });
    return res.status(401).json({ message: 'Not allowed' });
  }

  if (!verificationToken) {
    logger.warn(`Missing verification token ${req.body}`);
    await AuthEventService.log({
      userId: user.id,
      type: 'verify_otp_suspicious',
      req,
      metadata: { reason: 'Missing data' },
    });
    return res.status(401).json({ message: 'Not allowed' });
  }

  if (!email || !phone) {
    logger.warn(`Missing email or phone`);
    await AuthEventService.log({
      userId: user.id,
      type: 'verify_otp_suspicious',
      req,
      metadata: { reason: 'Missing data' },
    });
    return res.status(401).json({ message: 'Not allowed' });
  }

  const verificationResult = await verifyEmailOTP(user, verificationToken);

  user = verificationResult.user;
  const verified = verificationResult.verified;

  if (verified) {
    logger.info(`${email} is verified for login.`);
    await AuthEventService.log({
      userId: user.id,
      type: 'verify_otp_success',
      req,
    });

    let token, refreshToken, refreshTokenHash;

    if (user.phoneVerified && user.emailVerified && user.verified) {
      logger.info(`${email} is fully verified. Logging in...`);

      await AuthEventService.log({
        userId: user.id,
        type: 'verify_otp_success',
        req,
        metadata: { reason: 'User completed verification of phone and email' },
      });

      refreshToken = generateRefreshToken();
      refreshTokenHash = await hashRefreshToken(refreshToken);
      const { expiresAt, idleExpiresAt } = computeSessionTimes();

      const session = await Session.create({
        userId: user.id,
        infraId: process.env.APP_ID!,
        mode: AUTH_MODE,
        refreshTokenHash,
        userAgent: req.get('user-agent'),
        ipAddress: req.ip,
        expiresAt,
        idleExpiresAt,
        lastUsedAt: undefined,
      });

      token = await signAccessToken(session.id, user.id);
    }

    if (token && refreshToken) {
      try {
        await user.update({ lastLogin: new Date() });
      } catch (error) {
        logger.warn(`An error occured saving user last login - ${error}`);
      }
      if (AUTH_MODE === 'web') {
        await setAuthCookies(res, { accessToken: token, refreshToken: refreshTokenHash });
        return res.status(200).json({ message: 'Success' });
      }

      return res.status(200).json({ message: 'Success', token, refreshTokenHash });
    }
    return res.json({ message: 'Success' });
  } else {
    logger.error(
      `Verfication tokens did not match ${verificationToken} vs ${user.emailVerificationToken} or ${
        user.emailVerificationTokenExpiry
      } is less than ${new Date().getTime()}`,
    );
    await AuthEventService.log({
      userId: user.id,
      type: 'verify_otp_failed',
      req,
      metadata: { reason: 'User verification failed for phone' },
    });
  }

  return res.status(500).json({ message: 'Internal server error' });
};
