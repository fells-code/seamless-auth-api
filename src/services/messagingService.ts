/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import type { AuthMessagingService } from '@seamless-auth/messaging';

import { createDirectAuthMessagingService } from '../config/directMessaging.js';
import { getSystemConfig } from '../config/getSystemConfig.js';
import getLogger from '../utils/logger.js';
import { normalizePhoneNumber } from '../utils/utils.js';
import { DeliveryError } from './deliveryError.js';

const logger = getLogger('messaging');

function shouldBypassDirectMessaging() {
  // Not `=== 'development'`. Every other environment gate in the codebase asks whether
  // this is production, and testing for one name meant a staging, CI or unset NODE_ENV
  // tried to reach a real provider and failed the request that triggered it.
  const isProduction = process.env.NODE_ENV === 'production';
  const enableInDev = process.env.MESSAGING_ENABLE_IN_DEV === 'true';

  return !isProduction && !enableInDev;
}

// Built once and reused. Each construction builds a provider client per channel, so
// doing it per message threw away connection reuse and re-read configuration on every
// OTP. Keyed on app_name, which is the only input, so a config change still takes
// effect on the next send.
let cachedService: { appName: string; service: AuthMessagingService } | null = null;

async function getMessagingService() {
  const { app_name } = await getSystemConfig();

  if (cachedService?.appName === app_name) {
    return cachedService.service;
  }

  const service = createDirectAuthMessagingService(app_name);
  cachedService = { appName: app_name, service };

  return service;
}

export const sendOTPEmail = async (to: string, token: string) => {
  logger.debug('Sending verification email');

  if (shouldBypassDirectMessaging()) {
    logger.debug('Skipping direct email delivery in development');
    return;
  }

  try {
    const messaging = await getMessagingService();

    await messaging.sendOtpEmail({
      to,
      token,
    });

    logger.info('Verification email sent');
  } catch (error) {
    logger.error(`Failed to send verification email ${error}`);
    throw new DeliveryError('Failed to send verification email', error);
  }
};

export const sendOTPSMS = async (to: string, token: number) => {
  logger.debug('Sending verification SMS');

  if (shouldBypassDirectMessaging()) {
    logger.debug('Skipping direct SMS delivery in development');
    return;
  }

  try {
    const messaging = await getMessagingService();
    const normalizedPhone = normalizePhoneNumber(to);

    if (!normalizedPhone) {
      throw new Error('Invalid phone number for direct SMS delivery');
    }

    await messaging.sendOtpSms({
      to: normalizedPhone,
      token,
    });
  } catch (error) {
    logger.error(`Failed to send verification SMS ${error}`);
    throw new DeliveryError('Failed to send verification SMS', error);
  }
};

export const sendMagicLinkEmail = async (to: string, token: string, safeRedirect: string) => {
  logger.debug('Sending magic link');

  if (shouldBypassDirectMessaging()) {
    logger.debug('Skipping direct magic link delivery in development');
    return;
  }

  try {
    const messaging = await getMessagingService();

    await messaging.sendMagicLinkEmail({
      to,
      token,
      magicLinkUrl: safeRedirect,
    });
  } catch (error) {
    logger.error(`Failed to send magic link email ${error}`);
    throw new DeliveryError('Failed to send magic link email', error);
  }
};
