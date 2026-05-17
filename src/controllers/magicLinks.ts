/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import crypto from 'crypto';
import { Request, Response } from 'express';
import { Op } from 'sequelize';

import { getSystemConfig } from '../config/getSystemConfig.js';
import { AuthEvent } from '../models/authEvents.js';
import { MagicLinkToken } from '../models/magicLinks.js';
import { User } from '../models/users.js';
import { AuthEventService } from '../services/authEventService.js';
import { maybePromoteBootstrapAdmin } from '../services/bootstrapPromotionService.js';
import { getLoginPolicy, isLoginMethodEnabled } from '../services/loginPolicyService.js';
import { sendMagicLinkEmail } from '../services/messagingService.js';
import { issueSessionAndRespond } from '../services/sessionIssuance.js';
import { AuthenticatedRequest } from '../types/types.js';
import getLogger from '../utils/logger.js';
import { hashDeviceFingerprint, hashSha256 } from '../utils/utils.js';

const logger = getLogger('magic-links');

const TTL_MINUTES = 15;
const AUTH_MODE: 'web' | 'server' = process.env.AUTH_MODE! as 'web' | 'server';
const EXTERNAL_DELIVERY_HEADER = 'x-seamless-auth-delivery-mode';

function wantsExternalDelivery(req: Request) {
  return req.get(EXTERNAL_DELIVERY_HEADER)?.toLowerCase() === 'external';
}

async function rejectDisabledMagicLink(req: Request, res: Response, userId?: string | null) {
  const policy = await getLoginPolicy();

  if (isLoginMethodEnabled(policy, 'magic_link')) {
    return false;
  }

  await AuthEventService.log({
    userId: userId ?? null,
    type: 'login_failed',
    req,
    metadata: { reason: 'Login method disabled', method: 'magic_link' },
  });

  res.status(403).json({ error: 'login_method_disabled' });
  return true;
}

export async function requestMagicLink(req: Request, res: Response) {
  const authReq = req as AuthenticatedRequest;
  const preAuthUser = authReq.user;
  const useExternalDelivery = wantsExternalDelivery(req);

  if (await rejectDisabledMagicLink(req, res, preAuthUser?.id)) {
    return;
  }

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

  if (!ip_hash || !user_agent_hash) {
    logger.error('Could not identify devive metadata to send a magic link');
    return res.status(400).json({ error: 'Invalid device data' });
  }
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

  if (!useExternalDelivery) {
    await sendMagicLinkEmail(user.email, rawToken, redirect_url);
  }

  await AuthEventService.log({
    userId: user.id,
    type: 'magic_link_requested',
    req,
  });

  return res.json({
    message: 'If an account exists, a login link has been sent.',
    ...(useExternalDelivery
      ? {
          delivery: {
            kind: 'magic_link_email',
            to: user.email,
            token: rawToken,
            magicLinkUrl: redirect_url,
          },
        }
      : {}),
  });
}

export async function verifyMagicLink(req: Request, res: Response) {
  logger.debug('Verifying magic link');
  const { token } = req.params;

  if (await rejectDisabledMagicLink(req, res)) {
    return;
  }

  if (!token) {
    return res.status(400).json({ error: 'Missing verification token' });
  }
  const tokenHash = hashSha256(token);

  const record = await MagicLinkToken.findOne({
    where: { token_hash: tokenHash },
  });

  if (!record) {
    logger.warn(`No magic link found for token: ${token}`);
    return res.status(400).json({ error: 'Invalid verification token' });
  }

  if (record.used_at) {
    logger.warn(`Magic link token is already used ${token}`);
    return res.status(400).json({ error: 'Invalid verification token' });
  }

  if (record.expires_at < new Date()) {
    logger.warn(`Magic link token expired: ${token}`);
    return res.status(400).json({ error: 'Invalid verification token' });
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
    return res.status(500).json({ error: 'Failed to use token' });
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

  if (await rejectDisabledMagicLink(req, res, preAuthUser?.id)) {
    return;
  }

  const user = await User.findOne({ where: { email: preAuthUser.email } });

  if (!user) {
    return res.status(400).json({
      error: 'Failed',
    });
  }

  const record = await MagicLinkToken.findOne({
    where: { user_id: user.id, expires_at: { [Op.gt]: new Date() } },
  });

  if (!record) {
    logger.warn('No magic link token');
    return res.status(500).json({ error: 'Invalid request' });
  }

  // Device binding check
  const { ip_hash, user_agent_hash } = hashDeviceFingerprint(req.ip, req.headers['user-agent']);

  if (record.ip_hash && record.ip_hash !== ip_hash) {
    return res.status(500).json({ error: 'Invalid request' });
  }

  if (record.user_agent_hash && record.user_agent_hash !== user_agent_hash) {
    return res.status(500).json({ error: 'Invalid request' });
  }

  if (record.used_at && record.expires_at > new Date()) {
    await AuthEventService.log({
      userId: record.user_id,
      type: 'magic_link_poll_completed_successfully',
      req,
    });

    user.challenge = '';
    user.verified = true;

    await user.save();

    const bootstrapResult = await maybePromoteBootstrapAdmin({
      user,
      req,
      completionMethod: 'magic_link_fallback',
    });

    if (bootstrapResult.promoted) {
      logger.info(`Bootstrap admin granted to ${user.email}`);
    }

    await AuthEvent.create({
      user_id: user.id,
      type: 'registration_success',
      ip_address: req.ip,
      user_agent: req.headers['user-agent'],
      metadata: {},
    });

    await issueSessionAndRespond({
      user: {
        id: user.id,
        email: user.email,
        phone: user.phone,
        roles: user.roles ?? [],
      },
      req,
      res,
      authMode: AUTH_MODE,
      clearBootstrap: true,
    });

    user.update({
      lastLogin: new Date(),
    });

    return;
  }
  return res.status(204).json({ message: 'Success' });
}
