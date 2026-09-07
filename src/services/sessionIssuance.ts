/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { Request, Response } from 'express';

import { getSystemConfig } from '../config/getSystemConfig.js';
import { createRefreshTokenLookup, generateRefreshToken, signAccessToken } from '../lib/token.js';
import { Session } from '../models/sessions.js';
import { computeSessionTimes, parseDurationToSeconds } from '../utils/utils.js';
import { enforceConcurrentSessionLimit } from './concurrentSessionPolicy.js';
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
  /**
   * Fields the calling flow adds to the session response.
   *
   * Kept generic rather than naming OAuth's `returnTo` here, so session issuance does
   * not have to know which flow reached it. Each route validates its own response
   * against its declared schema, which is what keeps this from becoming a way to put
   * anything at all in the body.
   */
  extraFields?: Record<string, unknown>;
};

export async function issueSessionAndRespond(params: IssueSessionParams): Promise<void> {
  const { user, req, res, extraFields } = params;

  const refreshToken = generateRefreshToken();
  const refreshTokenLookup = createRefreshTokenLookup(refreshToken);
  const { access_token_ttl, refresh_token_ttl, session_idle_ttl, max_concurrent_sessions } =
    await getSystemConfig();
  const { expiresAt, idleExpiresAt } = computeSessionTimes({
    absoluteTtl: refresh_token_ttl || '1d',
    idleTtl: session_idle_ttl || '8h',
  });
  const organizationId = await getDefaultOrganizationIdForUser(user.id);

  // Before the row exists, so the limit counts the session about to be created.
  await enforceConcurrentSessionLimit({
    userId: user.id,
    limit: max_concurrent_sessions,
    req,
  });

  const session = await Session.create({
    userId: user.id,
    infraId: process.env.APP_ID!,
    organizationId,
    mode: 'server',
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
    refreshTtl: parseDurationToSeconds(refresh_token_ttl || '1d'),
    ...extraFields,
  });
}
