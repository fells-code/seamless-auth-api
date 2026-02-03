/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import { Request, Response } from 'express';
import { Op } from 'sequelize';

import { getSystemConfig } from '../config/getSystemConfig';
import { setAuthCookies } from '../lib/cookie';
import { signEphemeralToken } from '../lib/token';
import { AuthEvent } from '../models/authEvents';
import { User } from '../models/users';
import { AuthEventService } from '../services/authEventService';
import getLogger from '../utils/logger';
import { generateEmailOTP, generatePhoneOTP } from '../utils/otp';
import { isValidEmail, isValidPhoneNumber } from '../utils/utils';

const logger = getLogger('registration');
const AUTH_MODE = process.env.AUTH_MODE;

export const register = async (req: Request, res: Response) => {
  const { email, phone } = req.body;
  const systemConfig = await getSystemConfig();
  logger.info(`Registering phone and email account`);

  try {
    if (!email) {
      logger.error(`Missing email`);
      AuthEventService.log({
        userId: null,
        type: 'registration_suspicious',
        req,
        metadata: { reason: 'Missing required email.' },
      });
      return res.status(400).json({ message: 'Invalid data.' });
    }

    if (!phone) {
      logger.error(`Missing phone`);
      AuthEventService.log({
        userId: null,
        type: 'registration_suspicious',
        req,
        metadata: { reason: 'Missing required phone.' },
      });
      return res.status(400).json({ message: 'Invalid data.' });
    }

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
      logger.info(`Sending OTPs`);
      AuthEventService.log({
        userId: user.id,
        type: 'informational',
        req,
        metadata: { reason: 'Attempted registration with exisiting account.' },
      });

      token = await signEphemeralToken(user.id);

      await generateEmailOTP(user);
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

      logger.info(`Sending OTPs to  ${email} and ${phone}`);
      await generateEmailOTP(user);
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
    return res.status(500).json({ message: 'Internal server error' });
  }
};
