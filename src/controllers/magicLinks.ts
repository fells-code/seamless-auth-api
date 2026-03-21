/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import crypto from 'crypto';
import { Request, Response } from 'express';
import { Op } from 'sequelize';

import { getSystemConfig } from '../config/getSystemConfig.js';
import { setAuthCookies } from '../lib/cookie.js';
import { generateRefreshToken, hashRefreshToken, signAccessToken } from '../lib/token.js';
import { AuthEvent } from '../models/authEvents.js';
import { MagicLinkToken } from '../models/magicLinks.js';
import { Session } from '../models/sessions.js';
import { User } from '../models/users.js';
import { AuthEventService } from '../services/authEventService.js';
import { sendMagicLinkEmail } from '../services/messagingService.js';
import { AuthenticatedRequest } from '../types/types.js';
import getLogger from '../utils/logger.js';
import {
  computeSessionTimes,
  hashDeviceFingerprint,
  hashSha256,
  parseDurationToSeconds,
} from '../utils/utils.js';

const logger = getLogger('magic-links');

const TTL_MINUTES = 15;
const AUTH_MODE: 'web' | 'server' = process.env.AUTH_MODE! as 'web' | 'server';

export async function requestMagicLink(req: Request, res: Response) {
  const authReq = req as AuthenticatedRequest;
  const preAuthUser = authReq.user;

  const user = await User.findOne({ where: { email: preAuthUser.email } });

  if (!user) {
    return res.json({
      message: 'If an account exists, a login link has been sent.',
    });
  }

  const rawToken = crypto.randomBytes(32).toString('base64url');
  const tokenHash = hashSha256(rawToken);

  const config = await getSystemConfig();
  const redirect_url = `${config.origins[0]}/verify-magiclink?token=${rawToken}`;

  const { ip_hash, user_agent_hash } = hashDeviceFingerprint(req.ip, req.headers['user-agent']);

  // Expire all previous links
  await MagicLinkToken.update(
    { expires_at: new Date() },
    {
      where: {
        user_id: user.id,
      },
    },
  );

  await MagicLinkToken.create({
    user_id: user.id,
    token_hash: tokenHash,
    redirect_url,
    ip_hash,
    user_agent_hash,
    expires_at: new Date(Date.now() + TTL_MINUTES * 60 * 1000),
  });

  await sendMagicLinkEmail(user.email, rawToken, redirect_url);

  await AuthEventService.log({
    userId: user.id,
    type: 'magic_link_requested',
    req,
  });

  return res.json({
    message: 'If an account exists, a login link has been sent.',
  });
}

export async function verifyMagicLink(req: Request, res: Response) {
  logger.debug('Verifying magic link');
  const { token } = req.params;

  if (!token) {
    return res.status(400).json({ message: 'Missing verification token' });
  }
  const tokenHash = hashSha256(token);

  const record = await MagicLinkToken.findOne({
    where: { token_hash: tokenHash },
  });

  if (!record) {
    logger.warn(`No magic link found for token: ${token}`);
    return res.status(400).json({ message: 'Invalid verification token' });
  }

  if (record.used_at) {
    logger.warn(`Magic link token is already used ${token}`);
    return res.status(400).json({ message: 'Invalid verification token' });
  }

  if (record.expires_at < new Date()) {
    logger.warn(`Magic link token expired: ${token}`);
    return res.status(400).json({ message: 'Invalid verification token' });
  }

  // Atomic consume
  logger.info(`Magic link being consumed ${token}`);

  const [updated] = await MagicLinkToken.update(
    { used_at: new Date() },
    {
      where: {
        id: record.id,
        used_at: null,
      },
    },
  );

  if (!updated) {
    logger.error(`Magic link token was not consumted: ${token}`);
    return res.status(500).json({ message: 'Failed to use token' });
  }

  await AuthEventService.log({
    userId: record.user_id,
    type: 'magic_link_success',
    req,
    metadata: { message: `Token: ${token}` },
  });

  // Device binding check
  const { ip_hash, user_agent_hash } = hashDeviceFingerprint(req.ip, req.headers['user-agent']);

  if (record.ip_hash && record.ip_hash !== ip_hash) {
    return res.status(200).json({ message: 'Success' });
  }

  if (record.user_agent_hash && record.user_agent_hash !== user_agent_hash) {
    return res.status(200).json({ message: 'Success' });
  }

  return res.status(200).json({ message: 'Success' });
}

export async function pollMagicLinkConfirmation(req: Request, res: Response) {
  const authReq = req as AuthenticatedRequest;
  const preAuthUser = authReq.user;

  const user = await User.findOne({ where: { email: preAuthUser.email } });

  if (!user) {
    return res.status(400).json({
      message: 'Failed',
    });
  }

  const record = await MagicLinkToken.findOne({
    where: { user_id: user.id, expires_at: { [Op.gt]: new Date() } },
  });

  if (!record) {
    console.log('No magic link token');
    return res.status(500).json({ message: 'Invalid request' });
  }

  // Device binding check
  const { ip_hash, user_agent_hash } = hashDeviceFingerprint(req.ip, req.headers['user-agent']);

  if (record.ip_hash && record.ip_hash !== ip_hash) {
    return res.status(500).json({ message: 'Invalid request' });
  }

  if (record.user_agent_hash && record.user_agent_hash !== user_agent_hash) {
    return res.status(500).json({ message: 'Invalid request' });
  }

  if (record.used_at && record.expires_at > new Date()) {
    await AuthEventService.log({
      userId: record.user_id,
      type: 'magic_link_poll_completed_successfully',
      req,
    });

    const refreshToken = generateRefreshToken();
    const refreshTokenHash = await hashRefreshToken(refreshToken);
    const { expiresAt, idleExpiresAt } = computeSessionTimes();

    const session = await Session.create({
      userId: user.id,
      infraId: process.env.APP_ID!,
      mode: AUTH_MODE,
      refreshTokenHash,
      userAgent: req.get('user-agent'),
      ipAddress: req.ip,
      expiresAt,
      idleExpiresAt,
      lastUsedAt: undefined,
    });

    const token = await signAccessToken(session.id, user.id, user.roles);

    user.challenge = '';
    user.verified = true;

    await user.save();

    if (token && refreshToken) {
      await AuthEvent.create({
        user_id: user.id,
        type: 'registration_success',
        ip_address: req.ip,
        user_agent: req.headers['user-agent'],
        metadata: {},
      });

      if (AUTH_MODE === 'web') {
        await setAuthCookies(res, { accessToken: token, refreshToken });
        res.status(200).json({ message: 'Success' });
        return;
      }

      const { access_token_ttl, refresh_token_ttl } = await getSystemConfig();

      return res.status(200).json({
        message: 'Success',
        token,
        refreshToken,
        sub: user.id,
        roles: user.roles,
        email: user.email,
        phone: user.phone,
        ttl: parseDurationToSeconds(access_token_ttl || '15m'),
        refreshTtl: parseDurationToSeconds(refresh_token_ttl || '1h'),
      });
    }
  }

  return res.status(204).json({ message: 'Not verified.' });
}
