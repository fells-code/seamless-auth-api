/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { createDirectAuthMessagingService } from '../config/directMessaging.js';
import { getSystemConfig } from '../config/getSystemConfig.js';
import getLogger from '../utils/logger.js';
import { normalizePhoneNumber } from '../utils/utils.js';

const logger = getLogger('messaging');

function shouldBypassDirectMessaging() {
  const isDevelopment = process.env.NODE_ENV === 'development';
  const enableInDev = process.env.MESSAGING_ENABLE_IN_DEV === 'true';

  return isDevelopment && !enableInDev;
}

async function getMessagingService() {
  const { app_name } = await getSystemConfig();
  return createDirectAuthMessagingService(app_name);
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
    throw error;
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
    throw error;
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
    throw error;
  }
};

export const sendBootstrapEmail = async (to: string, url: string) => {
  logger.debug('Sending bootstrap invitation email');

  if (shouldBypassDirectMessaging()) {
    logger.debug('Skipping direct bootstrap delivery in development');
    return;
  }

  try {
    const messaging = await getMessagingService();

    await messaging.sendBootstrapInviteEmail({
      to,
      inviteUrl: url,
    });
  } catch (error) {
    logger.error(`Failed to send bootstrap invite email ${error}`);
    throw error;
  }
};
