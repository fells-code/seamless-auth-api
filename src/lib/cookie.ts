/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import { Response } from 'express';

import { getSystemConfig } from '../config/getSystemConfig';
import getLogger from '../utils/logger';
import { parseDurationToSeconds } from '../utils/utils';

const logger = getLogger('cookies');
export async function setAuthCookies(
  res: Response,
  cookie: {
    accessToken?: string;
    refreshToken?: string;
    ephemeralToken?: string;
  },
) {
  const { accessToken, refreshToken, ephemeralToken } = cookie;

  if (accessToken) {
    const { access_token_ttl } = await getSystemConfig();

    res.cookie('seamless_access', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      path: '/',
      maxAge: parseDurationToSeconds(access_token_ttl || '15m') * 1000,
    });
  }

  if (refreshToken) {
    const { refresh_token_ttl } = await getSystemConfig();
    res.cookie('seamless_refresh', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      maxAge: parseDurationToSeconds(refresh_token_ttl || '1h') * 1000,
    });
  }

  if (ephemeralToken) {
    res.cookie('seamless_ephemeral', ephemeralToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      maxAge: 5 * 60 * 1000,
    });
  }
}

export function clearAuthCookies(res: Response) {
  logger.debug('Cookies cleared');
  res.clearCookie('seamless_access', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
  });
  res.clearCookie('seamless_refresh', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
  });
  res.clearCookie('seamless_ephemeral', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
  });
}
