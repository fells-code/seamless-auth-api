/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { Request, Response } from 'express';

import { getSystemConfig } from '../config/getSystemConfig.js';
import { setBootstrapCookie } from '../lib/bootstrapCookie.js';
import { setAuthCookies } from '../lib/cookie.js';
import { signEphemeralToken } from '../lib/token.js';
import { AuthEvent } from '../models/authEvents.js';
import { User } from '../models/users.js';
import { AuthEventService } from '../services/authEventService.js';
import getLogger from '../utils/logger.js';
import { generatePhoneOTP } from '../utils/otp.js';
import { isValidEmail, isValidPhoneNumber, normalizePhoneNumber } from '../utils/utils.js';

const logger = getLogger('registration');
const AUTH_MODE = process.env.AUTH_MODE;
const EXTERNAL_DELIVERY_HEADER = 'x-seamless-auth-delivery-mode';

function wantsExternalDelivery(req: Request) {
  return req.get(EXTERNAL_DELIVERY_HEADER)?.toLowerCase() === 'external';
}

export const register = async (req: Request, res: Response) => {
  const { email, phone, bootstrapToken } = req.body;
  const useExternalDelivery = wantsExternalDelivery(req);
  const normalizedEmail = email?.toLowerCase();
  const normalizedPhone = typeof phone === 'string' ? normalizePhoneNumber(phone) : null;

  if (bootstrapToken && bootstrapToken.length > 10) {
    setBootstrapCookie(res, bootstrapToken);

    logger.info('Bootstrap token stored in cookie for registration flow');
  }

  const systemConfig = await getSystemConfig();
  logger.info(`Registering phone and email account`);

  try {
    if (!isValidEmail(email) || !isValidPhoneNumber(phone) || !normalizedPhone) {
      logger.error(`Invalid email or phone provided: ${email} - ${phone}`);
      await AuthEventService.log({
        userId: null,
        type: 'registration_suspicious',
        req,
        metadata: { reason: 'Bad data submitted.' },
      });

      return res.status(400).json({ message: 'Invalid data.' });
    }

    const [existingEmailUser, existingPhoneUser] = await Promise.all([
      User.findOne({ where: { email: normalizedEmail } }),
      User.findOne({ where: { phone: normalizedPhone } }),
    ]);

    const hasExactExistingUser =
      existingEmailUser && existingPhoneUser && existingEmailUser.id === existingPhoneUser.id;
    const hasIdentifierConflict =
      (existingEmailUser && !existingPhoneUser) ||
      (!existingEmailUser && existingPhoneUser) ||
      (existingEmailUser && existingPhoneUser && existingEmailUser.id !== existingPhoneUser.id);

    if (hasIdentifierConflict) {
      logger.warn(`Registration conflict for email ${normalizedEmail} and phone ${phone}`);
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

      return res.status(409).json({
        error: 'Registration conflict',
        message:
          'The provided email and phone do not belong to the same account. Try signing in with your existing account details or use a different email and phone.',
      });
    }

    let user = hasExactExistingUser ? existingEmailUser : null;

    let token;
    let phoneOtp: number | null = null;

    if (user) {
      logger.info(`Registration attempt for a user that already exisited`);
      logger.info(`Sending OTP`);
      await AuthEventService.log({
        userId: user.id,
        type: 'informational',
        req,
        metadata: { reason: 'Attempted registration with exisiting account.' },
      });

      token = await signEphemeralToken(user.id);

      phoneOtp = await generatePhoneOTP(user, {
        sendMessage: !useExternalDelivery,
      });
    } else {
      logger.info(`Creating new user`);

      user = await User.create({
        email: normalizedEmail,
        phone: normalizedPhone,
        roles: systemConfig.default_roles,
      });

      await AuthEventService.log({
        userId: user.id,
        type: 'user_created',
        req,
        metadata: { reason: 'New user registation.' },
      });

      token = await signEphemeralToken(user.id);

      await AuthEventService.notificationSent(user.id, req, {
        reason: 'Owner notified of new user registration',
      });

      logger.info(`Sending phone OTP to ${normalizedPhone}`);
      phoneOtp = await generatePhoneOTP(user, {
        sendMessage: !useExternalDelivery,
      });

      await AuthEventService.log({
        userId: user.id,
        type: 'registration_success',
        req,
        metadata: { reason: 'New user registration' },
      });
    }

    const delivery =
      useExternalDelivery && phoneOtp !== null
        ? {
            kind: 'otp_sms',
            to: normalizePhoneNumber(user.phone) ?? user.phone,
            token: phoneOtp,
          }
        : undefined;

    if (AUTH_MODE === 'web') {
      await setAuthCookies(res, { ephemeralToken: token });
      res.status(200).json({
        message: 'Success',
        ...(delivery ? { delivery } : {}),
      });
      return;
    }

    return res.status(200).json({
      message: 'Success',
      sub: user.id,
      token,
      ttl: '300',
      ...(delivery ? { delivery } : {}),
    });
  } catch (error: unknown) {
    if (error instanceof Error) {
      logger.error(`Error during registration for email ${email}: ${error}`);
    } else {
      logger.error(`Error during registration: ${String(error)}`);
    }

    await AuthEvent.create({
      user_id: null,
      type: 'registration_failed',
      ip_address: req.ip,
      user_agent: req.headers['user-agent'],
      metadata: { reason: 'Catch all error' },
    });
    return res.status(500).json({ error: 'Internal server error' });
  }
};
