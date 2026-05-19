/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { Request, Response } from 'express';

import { getSystemConfig } from '../config/getSystemConfig.js';
import { clearBootstrapCookie } from '../lib/bootstrapCookie.js';
import { clearAuthCookies, setAuthCookies } from '../lib/cookie.js';
import {
  createRefreshTokenLookup,
  generateRefreshToken,
  hashRefreshToken,
  signAccessToken,
} from '../lib/token.js';
import { Session } from '../models/sessions.js';
import { computeSessionTimes, parseDurationToSeconds } from '../utils/utils.js';
import { getDefaultOrganizationIdForUser } from './organizationService.js';

type IssueSessionParams = {
  user: {
    id: string;
    email: string;
    phone: string | null;
    roles: string[];
  };
  req: Request;
  res: Response;
  authMode: 'web' | 'server';
  clearBootstrap?: boolean;
  clearExistingCookies?: boolean;
};

export async function issueSessionAndRespond(params: IssueSessionParams): Promise<void> {
  const { user, req, res, authMode, clearBootstrap = false, clearExistingCookies = false } = params;

  const refreshToken = generateRefreshToken();
  const refreshTokenHash = await hashRefreshToken(refreshToken);
  const refreshTokenLookup = createRefreshTokenLookup(refreshToken);
  const { expiresAt, idleExpiresAt } = computeSessionTimes();
  const organizationId = await getDefaultOrganizationIdForUser(user.id);

  const session = await Session.create({
    userId: user.id,
    infraId: process.env.APP_ID!,
    organizationId,
    mode: authMode,
    refreshTokenHash,
    refreshTokenLookup,
    userAgent: req.get('user-agent'),
    ipAddress: req.ip,
    expiresAt,
    idleExpiresAt,
    lastUsedAt: undefined,
  });

  const token = await signAccessToken(session.id, user.id, user.roles, organizationId);

  if (!token || !refreshToken) {
    throw new Error('Failed to issue session tokens');
  }

  if (clearExistingCookies) {
    clearAuthCookies(res);
  }

  if (clearBootstrap) {
    clearBootstrapCookie(res);
  }

  if (authMode === 'web') {
    await setAuthCookies(res, { accessToken: token, refreshToken });
    res.status(200).json({ message: 'Success' });
    return;
  }

  const { access_token_ttl, refresh_token_ttl } = await getSystemConfig();

  res.status(200).json({
    message: 'Success',
    token,
    refreshToken,
    sub: user.id,
    organizationId,
    roles: user.roles,
    email: user.email,
    phone: user.phone,
    ttl: parseDurationToSeconds(access_token_ttl || '15m'),
    refreshTtl: parseDurationToSeconds(refresh_token_ttl || '1h'),
  });
}
