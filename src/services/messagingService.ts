/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import getLogger from '../utils/logger.js';

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

export const sendMagicLinkEmail = async (to: string, token: string, safeRedirect: string) => {
  logger.debug(`Sending magic link to: ${to}. URL: ${safeRedirect}`);

  if (isDevelopment) {
    return;
  }
};

export const sendBootstrapEmail = async (to: string, url: string) => {
  logger.debug(`Sending bootsrap invitation email to: ${to}. URL: ${url}`);

  if (isDevelopment) {
    return;
  }
};
