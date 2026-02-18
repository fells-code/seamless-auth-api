/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import getLogger from '../utils/logger';

const logger = getLogger('messaging');

const isDevelopment = process.env.NODE_ENV === 'development';

export const sendOTPEmail = async (to: string, token: string) => {
  logger.debug(`Sending verification email to: ${to} with ${token}`);

  if (isDevelopment) {
    return;
  }
};

export const sendOTPSMS = async (to: string, token: number) => {
  logger.debug(`Sending verification SMS: ${to} with ${token}`);

  if (isDevelopment) {
    return;
  }
};

export const sendMagicLinkEmail = async (to: string, token: string) => {
  logger.debug(`Sedning magic link to: ${to}. URL: ${token}`);

  if (isDevelopment) {
    return;
  }
};
