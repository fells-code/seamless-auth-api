/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { Request, Response } from 'express';

import getLogger from '../utils/logger.js';

const COOKIE_NAME = 'seamless_bootstrap_token';

const logger = getLogger('bootstrapCookie');

export function setBootstrapCookie(res: Response, token: string) {
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    maxAge: 15 * 60 * 1000,
    path: '/',
  });
}

export function getBootstrapCookie(req: Request): string | null {
  logger.debug(
    `Checking for bootstrap cookie. Cookie value: ${req.cookies?.[COOKIE_NAME] ?? null}`,
  );
  return req.cookies?.[COOKIE_NAME] ?? null;
}

export function clearBootstrapCookie(res: Response) {
  logger.debug(`Clearing bootstrap cookie.`);
  res.clearCookie(COOKIE_NAME, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    path: '/',
  });
}
