/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { Request, Response } from 'express';

import { canReturnExternalDelivery } from '../lib/externalDelivery.js';
import { signEphemeralToken } from '../lib/token.js';
import { AuthEventService } from '../services/authEventService.js';
import { rejectIfUserLocked } from '../services/lockoutPolicyService.js';
import {
  getLoginPolicy,
  isLoginMethodEnabled,
  type LoginMethod,
} from '../services/loginPolicyService.js';
import { issueSessionAndRespond } from '../services/sessionIssuance.js';
import { AuthenticatedRequest } from '../types/types.js';
import getLogger from '../utils/logger.js';
import {
  generateEmailOTP,
  generatePhoneOTP,
  verifyEmailOTP,
  verifyPhoneOTP,
} from '../utils/otp.js';
import { isValidEmail, isValidPhoneNumber, normalizePhoneNumber } from '../utils/utils.js';

const logger = getLogger('otp');

async function rejectDisabledLoginMethod(
  method: LoginMethod,
  req: Request,
  res: Response,
): Promise<boolean> {
  const policy = await getLoginPolicy();

  if (isLoginMethodEnabled(policy, method)) {
    return false;
  }

  const user = (req as AuthenticatedRequest).user;

  await AuthEventService.log({
    userId: user?.id ?? null,
    type: 'login_failed',
    req,
    metadata: { reason: 'Login method disabled', method },
  });

  res.status(403).json({ error: 'login_method_disabled' });
  return true;
}

export const sendPhoneOTP = async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const user = authReq.user;
  const phone = user.phone;
  const normalizedPhone = normalizePhoneNumber(phone);
  const useExternalDelivery = await canReturnExternalDelivery(req);

  if (!phone) {
    logger.warn(`Missing phone`);
    AuthEventService.log({
      userId: user.id,
      type: 'otp_suspicious',
      req,
      metadata: { reason: 'Missing required phone.' },
    });
    return res.status(400).json({ error: 'Invalid data' });
  }

  logger.info(`Sending OTP to phone number: ${phone}`);

  try {
    if (!isValidPhoneNumber(phone) || !normalizedPhone) {
      logger.warn(`Invalid phone provided: ${phone}`);
      AuthEventService.log({
        userId: null,
        type: 'otp_suspicious',
        req,
        metadata: { reason: 'Invalid phone number.' },
      });
      return res.status(400).json({ error: 'Invalid data' });
    }

    if (!user) {
      logger.error(`Attempted to send OTP to an unknown user: ${phone}`);
      AuthEventService.log({
        userId: null,
        type: 'otp_suspicious',
        req,
        metadata: { reason: 'Missing required phone.' },
      });
      return res.status(400).json({ error: 'Invalid data' });
    }

    logger.info(`${phone} requested a phone OTP`);
    const generatedToken = await generatePhoneOTP(user, {
      sendMessage: !useExternalDelivery,
    });

    AuthEventService.log({
      userId: null,
      type: 'otp_success',
      req,
    });

    const token = await signEphemeralToken(user.id);

    return res.status(200).json({
      message: 'success',
      token,
      ...(useExternalDelivery
        ? {
            delivery: {
              kind: 'otp_sms',
              to: normalizedPhone,
              token: generatedToken,
            },
          }
        : {}),
    });
  } catch (error: unknown) {
    if (error instanceof Error) {
      logger.error(`Error sending phone OTP ${error.message}`);
    } else {
      logger.error(`Error during registration: ${String(error)}`);
    }

    return res.status(500).json({ error: 'Internal server error' });
  }
};

export const sendEmailOTP = async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const user = authReq.user;
  const email = user.email;
  const useExternalDelivery = await canReturnExternalDelivery(req);

  try {
    if (!user) {
      logger.warn(`Attempted to send OTP to an unknown user: ${email}`);
      AuthEventService.log({
        userId: null,
        type: 'otp_suspicious',
        req,
        metadata: { reason: 'Missing required user.' },
      });
      return res.status(400).json({ error: 'Invalid data.' });
    }

    if (!email) {
      logger.warn(`Missing email`);
      AuthEventService.log({
        userId: null,
        type: 'otp_suspicious',
        req,
        metadata: { reason: 'Missing required email.' },
      });
      return res.status(400).json({ error: 'Invalid data.' });
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
      return res.status(400).json({ error: 'Invalid data.' });
    }

    logger.info(`${email} requested an email OTP`);
    const generatedToken = await generateEmailOTP(user, {
      sendMessage: !useExternalDelivery,
    });
    AuthEventService.log({
      userId: null,
      type: 'otp_success',
      req,
    });

    const token = await signEphemeralToken(user.id);

    return res.status(200).json({
      message: 'success',
      token,
      ...(useExternalDelivery
        ? {
            delivery: {
              kind: 'otp_email',
              to: email,
              token: generatedToken,
            },
          }
        : {}),
    });
  } catch (error: unknown) {
    if (error instanceof Error) {
      logger.error(`Error sending email OTP ${error.message}`);
    } else {
      logger.error(`Error during registration: ${String(error)}`);
    }

    return res.status(500).json({ error: 'Internal server error' });
  }
};

export const sendLoginPhoneOTP = async (req: Request, res: Response) => {
  if (await rejectDisabledLoginMethod('phone_otp', req, res)) {
    return;
  }

  return sendPhoneOTP(req, res);
};

export const sendLoginEmailOTP = async (req: Request, res: Response) => {
  if (await rejectDisabledLoginMethod('email_otp', req, res)) {
    return;
  }

  return sendEmailOTP(req, res);
};

export const verifyPhoneNumber = async (req: Request, res: Response) => {
  const { verificationToken } = req.body;

  const authReq = req as AuthenticatedRequest;
  let user = authReq.user;
  const email = user.email;
  const phone = user.phone;

  logger.info(`Verifying phone number: ${phone}`);

  if (!user || !user.phoneVerificationTokenExpiry || !user.phoneVerificationToken) {
    logger.warn('Failed to find a user for this phone verification token');
    await AuthEventService.log({
      userId: user.id,
      type: 'verify_otp_suspicious',
      req,
      metadata: { reason: 'Missing data' },
    });
    return res.status(401).json({ error: 'Failed to verify OTP' });
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
      return res.status(401).json({ error: 'Not Allowed.' });
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

      if (user.phoneVerified && user.emailVerified && user.verified) {
        logger.info(`${phone} is fully verified. Logging in...`);
        await AuthEventService.log({
          userId: user.id,
          type: 'verify_otp_success',
          req,
          metadata: { reason: 'User completed verification of phone and email' },
        });

        return res.status(200).json({ message: 'Success' });
      }
      res.json({ message: 'Success' });
    } else {
      logger.warn(`Verification tokens did not match or expired for phone verification`);
      return res.status(401).json({ error: 'Not allowed' });
    }
  } catch (error) {
    logger.error(`Failed to verify OTP: ${error}`);
    return res.status(500).json({ error: 'Internal server error' });
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
    logger.warn(`Failed to find a user for this email verification token`);
    await AuthEventService.log({
      userId: user.id,
      type: 'verify_otp_suspicious',
      req,
      metadata: { reason: 'Missing data' },
    });
    return res.status(401).json({ error: 'Invalid data.' });
  }

  if (!verificationToken) {
    logger.warn('Missing verification token');
    await AuthEventService.log({
      userId: user.id,
      type: 'verify_otp_suspicious',
      req,
      metadata: { reason: 'Missing data' },
    });
    return res.status(401).json({ error: 'Invalid data' });
  }

  if (!email || !phone) {
    logger.warn(`Missing email or phone`);
    await AuthEventService.log({
      userId: user.id,
      type: 'verify_otp_suspicious',
      req,
      metadata: { reason: 'Missing data' },
    });
    return res.status(401).json({ error: 'Invalid data' });
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

    if (user.phoneVerified && user.emailVerified && user.verified) {
      logger.info(`${email} is fully verified. Logging in...`);

      await AuthEventService.log({
        userId: user.id,
        type: 'verify_otp_success',
        req,
        metadata: { reason: 'User completed verification of phone and email' },
      });

      await issueSessionAndRespond({
        user: {
          id: user.id,
          email: user.email,
          phone: user.phone,
          roles: user.roles ?? [],
        },
        req,
        res,
      });

      user.update({
        lastLogin: new Date(),
      });

      return;
    }
    return res.json({ message: 'Success' });
  } else {
    logger.error(`Verification tokens did not match or expired for email verification`);
  }

  return res.status(500).json({ error: 'Internal server error' });
};

export const verifyLoginPhoneNumber = async (req: Request, res: Response) => {
  const { verificationToken } = req.body;
  const authReq = req as AuthenticatedRequest;
  let user = authReq.user;
  const email = user.email;
  const phone = user.phone;

  if (await rejectDisabledLoginMethod('phone_otp', req, res)) {
    return;
  }

  if (await rejectIfUserLocked({ userId: user.id, req, res })) {
    return;
  }

  logger.info(`Verifying login phone number: ${phone}`);

  if (!user || !user.phoneVerificationTokenExpiry || !user.phoneVerificationToken) {
    logger.warn('Failed to find a user for this phone verification token');
    await AuthEventService.log({
      userId: user.id,
      type: 'verify_otp_suspicious',
      req,
      metadata: { reason: 'Missing data' },
    });
    return res.status(401).json({ error: 'Not allowed' });
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
      return res.status(401).json({ error: 'Not Allowed.' });
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

      if (user.phoneVerified && user.emailVerified && user.verified) {
        logger.info(`${email} is fully verified. Logging in...`);

        await AuthEventService.log({
          userId: user.id,
          type: 'verify_otp_success',
          req,
          metadata: { reason: 'User completed verification of phone and email' },
        });

        await issueSessionAndRespond({
          user: {
            id: user.id,
            email: user.email,
            phone: user.phone,
            roles: user.roles ?? [],
          },
          req,
          res,
        });

        user.update({
          lastLogin: new Date(),
        });

        return;
      }
      return res.json({ message: 'Success' });
    } else {
      logger.warn(`Verification tokens did not match or expired for login phone verification`);
      await AuthEventService.log({
        userId: user.id,
        type: 'verify_otp_failed',
        req,
        metadata: { reason: 'User verification failed for phone' },
      });
      return res.status(401).json({ error: 'Not allowed' });
    }
  } catch (error) {
    logger.error(`Failed to verify OTP: ${error}`);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

export const verifyLoginEmail = async (req: Request, res: Response) => {
  const { verificationToken } = req.body;
  const authReq = req as AuthenticatedRequest;
  let user = authReq.user;
  const email = user.email;
  const phone = user.phone;

  if (await rejectDisabledLoginMethod('email_otp', req, res)) {
    return;
  }

  if (await rejectIfUserLocked({ userId: user.id, req, res })) {
    return;
  }

  logger.info(`Verifying login email: ${email}`);

  if (!user || !user.emailVerificationTokenExpiry || !user.emailVerificationToken) {
    logger.warn(`Failed to find a user for this email verification token`);
    await AuthEventService.log({
      userId: user.id,
      type: 'verify_otp_suspicious',
      req,
      metadata: { reason: 'Missing data' },
    });
    return res.status(401).json({ error: 'Not allowed' });
  }

  if (!verificationToken) {
    logger.warn('Missing verification token');
    await AuthEventService.log({
      userId: user.id,
      type: 'verify_otp_suspicious',
      req,
      metadata: { reason: 'Missing data' },
    });
    return res.status(401).json({ error: 'Not allowed' });
  }

  if (!email || !phone) {
    logger.warn(`Missing email or phone`);
    await AuthEventService.log({
      userId: user.id,
      type: 'verify_otp_suspicious',
      req,
      metadata: { reason: 'Missing data' },
    });
    return res.status(401).json({ error: 'Not allowed' });
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

    if (user.phoneVerified && user.emailVerified && user.verified) {
      logger.info(`${email} is fully verified. Logging in...`);

      await AuthEventService.log({
        userId: user.id,
        type: 'verify_otp_success',
        req,
        metadata: { reason: 'User completed verification of phone and email' },
      });

      await issueSessionAndRespond({
        user: {
          id: user.id,
          email: user.email,
          phone: user.phone,
          roles: user.roles ?? [],
        },
        req,
        res,
      });

      user.update({
        lastLogin: new Date(),
      });

      return;
    }
    return res.json({ message: 'Success' });
  } else {
    logger.error(`Verification tokens did not match or expired for login email verification`);
    await AuthEventService.log({
      userId: user.id,
      type: 'verify_otp_failed',
      req,
      metadata: { reason: 'User verification failed for phone' },
    });
  }

  return res.status(500).json({ error: 'Internal server error' });
};
