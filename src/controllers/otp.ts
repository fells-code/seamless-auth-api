/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { Request, Response } from 'express';

import { canReturnExternalDelivery } from '../lib/externalDelivery.js';
import { reviewAccountMetadata } from '../lib/reviewAccounts.js';
import { signEphemeralToken } from '../lib/token.js';
import { AuthEventService } from '../services/authEventService.js';
import { rejectWeakFactorForBreakGlass } from '../services/breakGlassService.js';
import { DeliveryError } from '../services/deliveryError.js';
import { passkeyEnrollmentPrompt } from '../services/enrollmentService.js';
import { rejectIfUserLocked } from '../services/lockoutPolicyService.js';
import {
  getLoginPolicy,
  isLoginMethodEnabled,
  isPasskeyRequiredForUser,
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
  const user = (req as AuthenticatedRequest).user;

  if (await rejectWeakFactorForBreakGlass(user, method, req, res)) {
    return true;
  }

  if (
    isLoginMethodEnabled(policy, method) &&
    !(user?.id && (await isPasskeyRequiredForUser(user.id, policy)))
  ) {
    return false;
  }

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
  const useExternalDelivery = await canReturnExternalDelivery(req);

  if (!phone) {
    logger.warn(`Missing phone`);
    await AuthEventService.log({
      userId: user.id,
      type: 'otp_suspicious',
      req,
      metadata: { reason: 'Missing required phone.' },
    });
    return res.status(400).json({ error: 'Invalid data' });
  }

  logger.info('Sending phone OTP');

  try {
    const normalizedPhone = normalizePhoneNumber(phone);

    if (!isValidPhoneNumber(phone) || !normalizedPhone) {
      logger.warn('Invalid phone provided');
      await AuthEventService.log({
        userId: user.id,
        type: 'otp_suspicious',
        req,
        metadata: { reason: 'Invalid phone number.' },
      });
      return res.status(400).json({ error: 'Invalid data' });
    }

    logger.info('User requested a phone OTP');
    const generatedToken = await generatePhoneOTP(user, {
      sendMessage: !useExternalDelivery,
    });

    await AuthEventService.log({
      userId: user.id,
      type: 'otp_success',
      req,
      metadata: { channel: 'sms' },
    });

    // Re-minted with the attempt it arrived on, so a resend does not start a new one.
    const token = await signEphemeralToken(user.id, authReq.attemptId);

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
    if (error instanceof DeliveryError) {
      await AuthEventService.log({
        userId: user.id,
        type: 'otp_failed',
        req,
        metadata: { reason: 'Delivery failed', channel: 'sms' },
      });
    }

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
    if (!email) {
      logger.warn(`Missing email`);
      await AuthEventService.log({
        userId: user.id,
        type: 'otp_suspicious',
        req,
        metadata: { reason: 'Missing required email.' },
      });
      return res.status(400).json({ error: 'Invalid data.' });
    }

    logger.info('Sending email OTP');

    if (!isValidEmail(email)) {
      logger.error('Invalid email provided');
      await AuthEventService.log({
        userId: user.id,
        type: 'otp_suspicious',
        req,
        metadata: { reason: 'Invalid email.' },
      });
      return res.status(400).json({ error: 'Invalid data.' });
    }

    logger.info('User requested an email OTP');
    const generatedToken = await generateEmailOTP(user, {
      sendMessage: !useExternalDelivery,
    });
    await AuthEventService.log({
      userId: user.id,
      type: 'otp_success',
      req,
      metadata: { channel: 'email', ...reviewAccountMetadata(email) },
    });

    const token = await signEphemeralToken(user.id, authReq.attemptId);

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
    if (error instanceof DeliveryError) {
      await AuthEventService.log({
        userId: user.id,
        type: 'otp_failed',
        req,
        metadata: { reason: 'Delivery failed', channel: 'email', ...reviewAccountMetadata(email) },
      });
    }

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

  const user = (req as AuthenticatedRequest).user;

  // Answered as for an account with no phone, which is what `/login` offered it.
  if (user.phone && !user.phoneVerified) {
    await AuthEventService.log({
      userId: user.id,
      type: 'otp_suspicious',
      req,
      metadata: { reason: 'Login phone OTP requested for an unverified phone.' },
    });
    return res.status(400).json({ error: 'Invalid data' });
  }

  return sendPhoneOTP(req, res);
};

/**
 * Proving a phone on an account that already signs in changes what it can sign in with,
 * which takes an access session (`/registration/phone`). The pre-auth token here can come
 * from an email address alone, so for a verified account nothing is sent and the answer
 * is the one a decoy gives.
 */
export const sendRegistrationPhoneOTP = async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const user = authReq.user;

  if (user.verified && user.phone) {
    await AuthEventService.log({
      userId: user.id,
      type: 'otp_suspicious',
      req,
      metadata: { reason: 'Registration phone OTP requested for a verified account.' },
    });
    const token = await signEphemeralToken(user.id, authReq.attemptId);
    return res.status(200).json({ message: 'success', token });
  }

  return sendPhoneOTP(req, res);
};

export const sendRegistrationEmailOTP = async (req: Request, res: Response) => {
  const user = (req as AuthenticatedRequest).user;

  if (user.verified && (await rejectDisabledLoginMethod('email_otp', req, res))) {
    return;
  }

  return sendEmailOTP(req, res);
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
  const phone = user.phone;

  logger.info('Verifying phone number');

  // See sendRegistrationPhoneOTP. A code sent before the account was claimed must not
  // verify a phone on it afterwards.
  if (user.verified) {
    await AuthEventService.log({
      userId: user.id,
      type: 'verify_otp_suspicious',
      req,
      metadata: { reason: 'Registration phone verification on a verified account.' },
    });
    return res.status(401).json({ error: 'Not allowed' });
  }

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
    if (!verificationToken || !phone) {
      logger.warn(`Missing data from verify phone numnber request.`);
      await AuthEventService.log({
        userId: user.id,
        type: 'verify_otp_suspicious',
        req,
        metadata: { reason: 'Missing data' },
      });
      return res.status(401).json({ error: 'Not Allowed.' });
    }

    const verificationResult = await verifyPhoneOTP(user, verificationToken, authReq.attemptId);

    user = verificationResult.user;
    const verified = verificationResult.verified;

    if (verified) {
      logger.info('User verified their phone number');
      await AuthEventService.log({
        userId: user.id,
        type: 'verify_otp_success',
        req,
        metadata: { reason: 'User verified their phone number', channel: 'sms' },
      });

      if (user.phoneVerified && user.emailVerified && user.verified) {
        logger.info('User is fully verified. Logging in...');
        await AuthEventService.log({
          userId: user.id,
          type: 'verify_otp_success',
          req,
          metadata: { reason: 'User completed verification of phone and email', channel: 'sms' },
        });

        return res.status(200).json({ message: 'Success' });
      }
      res.json({ message: 'Success' });
    } else {
      logger.warn(`Verification tokens did not match or expired for phone verification`);
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

export const verifyEmail = async (req: Request, res: Response) => {
  const { verificationToken } = req.body;
  const authReq = req as AuthenticatedRequest;
  let user = authReq.user;
  const email = user.email;

  // For an account that was already verified this endpoint is a login whatever its name
  // says, so the lockout policy and the login method list bind here as they do on
  // /otp/verify-login-email-otp. Only an unverified account skips the method list, since
  // email OTP is how registration proves an address whether or not the deployment
  // offers it as a way to sign in.
  if (await rejectIfUserLocked({ userId: user.id, req, res })) {
    return;
  }

  const wasVerified = Boolean(user.verified);

  if (wasVerified && (await rejectWeakFactorForBreakGlass(user, 'email_otp', req, res))) {
    return;
  }

  if (wasVerified && (await rejectDisabledLoginMethod('email_otp', req, res))) {
    return;
  }

  logger.info('Verifying email');

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

  if (!email) {
    logger.warn(`Missing email`);
    await AuthEventService.log({
      userId: user.id,
      type: 'verify_otp_suspicious',
      req,
      metadata: { reason: 'Missing data' },
    });
    return res.status(401).json({ error: 'Invalid data' });
  }

  const verificationResult = await verifyEmailOTP(user, verificationToken, authReq.attemptId);

  user = verificationResult.user;
  const verified = verificationResult.verified;

  if (verified) {
    logger.info('User verified their email');
    await AuthEventService.log({
      userId: user.id,
      type: 'verify_otp_success',
      req,
      metadata: {
        reason: 'User verified their email',
        channel: 'email',
        ...reviewAccountMetadata(email),
      },
    });

    if (user.emailVerified && user.verified) {
      logger.info('User is fully verified. Logging in...');

      await AuthEventService.log({
        userId: user.id,
        type: 'verify_otp_success',
        req,
        metadata: {
          reason: 'User completed email verification',
          channel: 'email',
          ...reviewAccountMetadata(email),
        },
      });

      await issueSessionAndRespond({
        method: 'email_otp',
        accountVerification: !wasVerified,
        user: {
          id: user.id,
          email: user.email,
          phone: user.phone,
          roles: user.roles ?? [],
        },
        req,
        res,
        extraFields: await passkeyEnrollmentPrompt(user.id),
      });

      await user.update({
        lastLogin: new Date(),
      });

      return;
    }
    return res.json({ message: 'Success' });
  } else {
    logger.error(`Verification tokens did not match or expired for email verification`);
    await AuthEventService.log({
      userId: user.id,
      type: 'verify_otp_failed',
      req,
      metadata: { reason: 'User verification failed for email', ...reviewAccountMetadata(email) },
    });
    return res.status(401).json({ error: 'Not allowed' });
  }
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

  logger.info('Verifying login phone number');

  // A code sent to an unverified phone, through registration before the account was
  // claimed, is not a sign-in.
  if (!user.phoneVerified) {
    await AuthEventService.log({
      userId: user.id,
      type: 'verify_otp_suspicious',
      req,
      metadata: { reason: 'Login phone verification for an unverified phone.' },
    });
    return res.status(401).json({ error: 'Not allowed' });
  }

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
      logger.info('User phone is verified for login.');
      await AuthEventService.log({
        userId: user.id,
        type: 'verify_otp_success',
        req,
        metadata: { channel: 'sms' },
      });

      if (user.phoneVerified && user.emailVerified && user.verified) {
        logger.info('User is fully verified. Logging in...');

        await AuthEventService.log({
          userId: user.id,
          type: 'verify_otp_success',
          req,
          metadata: { reason: 'User completed verification of phone and email', channel: 'sms' },
        });

        await issueSessionAndRespond({
          method: 'phone_otp',
          user: {
            id: user.id,
            email: user.email,
            phone: user.phone,
            roles: user.roles ?? [],
          },
          req,
          res,
          extraFields: await passkeyEnrollmentPrompt(user.id),
        });

        await user.update({
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

  if (await rejectDisabledLoginMethod('email_otp', req, res)) {
    return;
  }

  if (await rejectIfUserLocked({ userId: user.id, req, res })) {
    return;
  }

  logger.info('Verifying login email');

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

  if (!email) {
    logger.warn(`Missing email`);
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
    logger.info('User email is verified for login.');
    await AuthEventService.log({
      userId: user.id,
      type: 'verify_otp_success',
      req,
      metadata: { channel: 'email', ...reviewAccountMetadata(email) },
    });

    if (user.emailVerified && user.verified) {
      logger.info('User is fully verified. Logging in...');

      await AuthEventService.log({
        userId: user.id,
        type: 'verify_otp_success',
        req,
        metadata: {
          reason: 'User completed email verification',
          channel: 'email',
          ...reviewAccountMetadata(email),
        },
      });

      await issueSessionAndRespond({
        method: 'email_otp',
        user: {
          id: user.id,
          email: user.email,
          phone: user.phone,
          roles: user.roles ?? [],
        },
        req,
        res,
        extraFields: await passkeyEnrollmentPrompt(user.id),
      });

      await user.update({
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
      metadata: { reason: 'User verification failed for email', ...reviewAccountMetadata(email) },
    });
    return res.status(401).json({ error: 'Not allowed' });
  }
};
