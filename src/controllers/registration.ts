/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { Request, Response } from 'express';
import { Op } from 'sequelize';

import { getSystemConfig } from '../config/getSystemConfig.js';
import { setBootstrapCookie } from '../lib/bootstrapCookie.js';
import { setAuthCookies } from '../lib/cookie.js';
import { signEphemeralToken } from '../lib/token.js';
import { AuthEvent } from '../models/authEvents.js';
import { User } from '../models/users.js';
import { AuthEventService } from '../services/authEventService.js';
import getLogger from '../utils/logger.js';
import { generatePhoneOTP } from '../utils/otp.js';
import { isValidEmail, isValidPhoneNumber } from '../utils/utils.js';

const logger = getLogger('registration');
const AUTH_MODE = process.env.AUTH_MODE;

export const register = async (req: Request, res: Response) => {
  const { email, phone, bootstrapToken } = req.body;

  if (bootstrapToken && bootstrapToken.length > 10) {
    setBootstrapCookie(res, bootstrapToken);

    logger.info('Bootstrap token stored in cookie for registration flow');
  }

  const systemConfig = await getSystemConfig();
  logger.info(`Registering phone and email account`);

  try {
    if (!isValidEmail(email) || !isValidPhoneNumber(phone)) {
      logger.error(`Invalid email or phone provided: ${email} - ${phone}`);
      AuthEventService.log({
        userId: null,
        type: 'registration_suspicious',
        req,
        metadata: { reason: 'Bad data submitted.' },
      });

      return res.status(400).json({ message: 'Invalid data.' });
    }

    const now = new Date();
    now.setMinutes(now.getMinutes() + 5);

    let user = await User.findOne({
      where: {
        [Op.or]: [{ email: email.toLowerCase() }, { phone: phone }],
      },
    });

    let token;

    if (user) {
      logger.info(`Registration attempt for a user that already exisited`);
      logger.info(`Sending OTP`);
      AuthEventService.log({
        userId: user.id,
        type: 'informational',
        req,
        metadata: { reason: 'Attempted registration with exisiting account.' },
      });

      token = await signEphemeralToken(user.id);

      await generatePhoneOTP(user);
    } else {
      logger.info(`Creating new user`);

      user = await User.create({
        email: email.toLowerCase(),
        phone,
        roles: systemConfig.default_roles,
      });

      AuthEventService.log({
        userId: user.id,
        type: 'user_created',
        req,
        metadata: { reason: 'New user registation.' },
      });

      token = await signEphemeralToken(user.id);

      AuthEventService.notificationSent(user.id, req, {
        reason: 'Owner notified of new user registration',
      });

      logger.info(`Sending phone OTP to ${phone}`);
      await generatePhoneOTP(user);

      AuthEventService.log({
        userId: user.id,
        type: 'registration_success',
        req,
        metadata: { reason: 'New user registration' },
      });
    }

    if (AUTH_MODE === 'web') {
      await setAuthCookies(res, { ephemeralToken: token });
      res.status(200).json({ message: 'Success' });
      return;
    }

    return res.status(200).json({ message: 'Success', sub: user.id, token, ttl: '300' });
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
