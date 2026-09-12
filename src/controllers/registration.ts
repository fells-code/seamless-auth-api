/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { randomUUID } from 'crypto';
import { Request, Response } from 'express';
import { UniqueConstraintError } from 'sequelize';

import { getSystemConfig } from '../config/getSystemConfig.js';
import { canReturnExternalDelivery } from '../lib/externalDelivery.js';
import { withOwnerAdminRole } from '../lib/ownerAdmin.js';
import { signEphemeralToken } from '../lib/token.js';
import { User } from '../models/users.js';
import { AuthEventService } from '../services/authEventService.js';
import { DeliveryError } from '../services/deliveryError.js';
import { AuthenticatedRequest } from '../types/types.js';
import getLogger from '../utils/logger.js';
import { generateEmailOTP, generatePhoneOTP, verifyPhoneOTP } from '../utils/otp.js';
import { isValidEmail, isValidPhoneNumber, normalizePhoneNumber } from '../utils/utils.js';

const logger = getLogger('registration');

/**
 * Recorded as the OTP send it is, the same as a send from `/otp/*`, so every code that
 * goes out is one `otp_success` row. A send the provider refused is recorded against
 * the address it was for before the catch-all turns it into a server fault, since
 * that is the reading deliverability is measured from.
 */
async function sendRegistrationEmailOtp(
  user: User,
  req: Request,
  attemptId: string,
  sendMessage: boolean,
) {
  let otp: string;

  try {
    otp = await generateEmailOTP(user, { sendMessage });
  } catch (error) {
    if (error instanceof DeliveryError) {
      await AuthEventService.log({
        userId: user.id,
        attemptId,
        subjectEmail: user.email,
        type: 'otp_failed',
        req,
        metadata: { reason: 'Delivery failed', channel: 'email' },
      });
    }

    throw error;
  }

  await AuthEventService.log({
    userId: user.id,
    attemptId,
    subjectEmail: user.email,
    type: 'otp_success',
    req,
    metadata: { channel: 'email' },
  });

  return otp;
}

export const register = async (req: Request, res: Response) => {
  const { email, phone } = req.body;
  const useExternalDelivery = await canReturnExternalDelivery(req);
  // Registration starts an attempt the same way `/login` does: the row that records
  // it carries the id the token is minted with.
  const attemptId = randomUUID();
  const normalizedEmail = email?.toLowerCase();
  const phoneProvided = typeof phone === 'string' && phone.trim().length > 0;
  const normalizedPhone = phoneProvided ? normalizePhoneNumber(phone) : null;

  const systemConfig = await getSystemConfig();
  logger.info(`Registering email account`);

  try {
    if (!isValidEmail(email)) {
      logger.error('Invalid email provided during registration');
      await AuthEventService.log({
        userId: null,
        type: 'registration_suspicious',
        req,
        metadata: { reason: 'Bad data submitted.' },
      });

      return res.status(400).json({ error: 'Invalid data.', message: 'Invalid data.' });
    }

    if (phoneProvided && (!isValidPhoneNumber(phone) || !normalizedPhone)) {
      logger.error('Invalid optional phone provided during registration');
      await AuthEventService.log({
        userId: null,
        type: 'registration_suspicious',
        req,
        metadata: { reason: 'Bad phone submitted.' },
      });

      return res.status(400).json({ error: 'Invalid data.', message: 'Invalid data.' });
    }

    const [existingEmailUser, existingPhoneUser] = await Promise.all([
      User.findOne({ where: { email: normalizedEmail } }),
      normalizedPhone ? User.findOne({ where: { phone: normalizedPhone } }) : Promise.resolve(null),
    ]);

    // Recorded rather than refused. Answering 409 told an unauthenticated caller whether
    // an email was already registered, which is the enumeration oracle `/login` goes to
    // some length to close, reopened on another endpoint. Every outcome now returns the
    // same 200 shape, and the mismatch survives for operators in the audit trail.
    const hasIdentifierConflict =
      (Boolean(existingEmailUser) && phoneProvided && !existingPhoneUser) ||
      (!existingEmailUser && existingPhoneUser) ||
      (existingEmailUser && existingPhoneUser && existingEmailUser.id !== existingPhoneUser.id);

    if (hasIdentifierConflict) {
      logger.warn('Registration conflict for supplied identifiers');
      await AuthEventService.log({
        userId: existingEmailUser?.id ?? existingPhoneUser?.id ?? null,
        type: 'registration_suspicious',
        req,
        metadata: {
          reason: 'Registration attempted with mismatched existing identifiers.',
          emailInUse: Boolean(existingEmailUser),
          phoneInUse: Boolean(existingPhoneUser),
        },
      });
    }

    // A phone already held by another account is dropped rather than attached, so a
    // conflicting one cannot change the answer or breach the unique constraint.
    const attachablePhone = existingPhoneUser ? null : normalizedPhone;

    let user: User;
    let created = false;

    if (existingEmailUser) {
      user = existingEmailUser;
    } else {
      logger.info(`Creating new user`);

      try {
        user = await User.create({
          email: normalizedEmail,
          phone: attachablePhone,
          roles: withOwnerAdminRole(
            systemConfig.default_roles,
            normalizedEmail,
            systemConfig.available_roles,
          ),
        });
        created = true;
      } catch (error: unknown) {
        // The lookup above and this insert are two statements, and double clicking
        // Register is enough for both requests to pass the lookup. The account the index
        // refuses this one for is the one the other request just created, so this request
        // continues as though the lookup had found it, which a moment later it would
        // have. Answering 500 told the person who created the account that it had failed,
        // and recorded registration_failed for a registration that succeeded.
        if (!(error instanceof UniqueConstraintError)) throw error;

        const raced = await User.findOne({ where: { email: normalizedEmail } });

        // Something other than this address, so there is no account to continue as. The
        // unique index on phone is the only other one an insert here can breach.
        if (!raced) throw error;

        logger.info('Registration raced another request for the same address');
        user = raced;
      }
    }

    let token;
    let emailOtp: string | null = null;

    if (!created) {
      logger.info(`Registration attempt for a user that already exisited`);
      logger.info(`Sending email OTP`);
      await AuthEventService.log({
        userId: user.id,
        attemptId,
        subjectEmail: user.email,
        type: 'informational',
        req,
        metadata: { reason: 'Attempted registration with exisiting account.' },
      });

      token = await signEphemeralToken(user.id, attemptId);

      emailOtp = await sendRegistrationEmailOtp(user, req, attemptId, !useExternalDelivery);
    } else {
      await AuthEventService.log({
        userId: user.id,
        attemptId,
        subjectEmail: user.email,
        type: 'user_created',
        req,
        metadata: { reason: 'New user registation.' },
      });

      token = await signEphemeralToken(user.id, attemptId);

      await AuthEventService.notificationSent(user.id, req, {
        reason: 'Owner notified of new user registration',
      });

      logger.info('Sending email OTP for registration');
      emailOtp = await sendRegistrationEmailOtp(user, req, attemptId, !useExternalDelivery);

      await AuthEventService.log({
        userId: user.id,
        attemptId,
        subjectEmail: user.email,
        type: 'registration_success',
        req,
        metadata: { reason: 'New user registration' },
      });
    }

    const delivery =
      useExternalDelivery && emailOtp !== null
        ? {
            kind: 'otp_email' as const,
            to: user.email,
            token: emailOtp,
          }
        : undefined;

    return res.status(200).json({
      message: 'Success',
      sub: user.id,
      token,
      // Seconds, and it has to match the `5m` in signEphemeralToken. A caller
      // sets its registration cookie from this, so a larger value here leaves a
      // cookie outliving the token it carries.
      ttl: 300,
      ...(delivery ? { delivery } : {}),
    });
  } catch (error: unknown) {
    if (error instanceof Error) {
      logger.error(`Error during registration: ${error}`);
    } else {
      logger.error(`Error during registration: ${String(error)}`);
    }

    await AuthEventService.log({
      userId: null,
      type: 'registration_failed',
      req,
      metadata: { reason: 'Catch all error' },
    });
    return res.status(500).json({ error: 'Internal server error' });
  }
};

export const registerPhone = async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const user = authReq.user;
  const { phone } = req.body;
  const normalizedPhone = typeof phone === 'string' ? normalizePhoneNumber(phone) : null;
  const useExternalDelivery = await canReturnExternalDelivery(req);

  if (!user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    if (!phone || !isValidPhoneNumber(phone) || !normalizedPhone) {
      logger.warn('Invalid phone provided for phone registration');
      await AuthEventService.log({
        userId: user.id,
        type: 'registration_suspicious',
        req,
        metadata: { reason: 'Invalid phone number.' },
      });

      return res.status(400).json({ error: 'Invalid data' });
    }

    const existingPhoneUser = await User.findOne({ where: { phone: normalizedPhone } });

    if (existingPhoneUser && existingPhoneUser.id !== user.id) {
      await AuthEventService.log({
        userId: user.id,
        type: 'registration_suspicious',
        req,
        metadata: { reason: 'Phone registration attempted with an in-use phone number.' },
      });

      return res.status(409).json({
        error: 'Phone number in use',
        message: 'The provided phone number is already registered to another account.',
      });
    }

    const phoneChanged = user.phone !== normalizedPhone;

    await user.update({
      phone: normalizedPhone,
      phoneVerified: phoneChanged ? false : user.phoneVerified,
      phoneVerificationToken: null,
      phoneVerificationTokenExpiry: null,
    });

    user.phone = normalizedPhone;
    if (phoneChanged) {
      user.phoneVerified = false;
    }

    const shouldSendVerification = phoneChanged || !user.phoneVerified;
    const phoneOtp = shouldSendVerification
      ? await generatePhoneOTP(user, { sendMessage: !useExternalDelivery })
      : null;

    await AuthEventService.log({
      userId: user.id,
      type: 'registration_success',
      req,
      metadata: { reason: 'User registered a phone number.' },
    });

    const delivery =
      useExternalDelivery && phoneOtp !== null
        ? {
            kind: 'otp_sms' as const,
            to: normalizedPhone,
            token: phoneOtp,
          }
        : undefined;

    return res.status(200).json({
      message: 'Success',
      phone: normalizedPhone,
      ...(delivery ? { delivery } : {}),
    });
  } catch (error: unknown) {
    logger.error(`Error during phone registration: ${String(error)}`);
    await AuthEventService.log({
      userId: user.id,
      type: 'registration_failed',
      req,
      metadata: { reason: 'Failed to register phone number.' },
    });

    return res.status(500).json({ error: 'Internal server error' });
  }
};

export const verifyRegisteredPhone = async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const user = authReq.user;
  const { verificationToken } = req.body;

  if (!user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  if (!user.phone || !user.phoneVerificationTokenExpiry || !user.phoneVerificationToken) {
    await AuthEventService.log({
      userId: user.id,
      type: 'verify_otp_suspicious',
      req,
      metadata: { reason: 'Missing phone verification data.' },
    });

    return res.status(401).json({ error: 'Failed to verify OTP' });
  }

  if (!verificationToken) {
    await AuthEventService.log({
      userId: user.id,
      type: 'verify_otp_suspicious',
      req,
      metadata: { reason: 'Missing verification token.' },
    });

    return res.status(401).json({ error: 'Not allowed' });
  }

  try {
    const verificationResult = await verifyPhoneOTP(user, verificationToken);

    if (!verificationResult.verified) {
      await AuthEventService.log({
        userId: user.id,
        type: 'verify_otp_failed',
        req,
        metadata: { reason: 'User verification failed for phone.' },
      });

      return res.status(401).json({ error: 'Not allowed' });
    }

    await AuthEventService.log({
      userId: user.id,
      type: 'verify_otp_success',
      req,
      metadata: { reason: 'User verified their phone number.' },
    });

    return res.status(200).json({ message: 'Success' });
  } catch (error: unknown) {
    logger.error(`Failed to verify registered phone: ${String(error)}`);
    return res.status(500).json({ error: 'Internal server error' });
  }
};
