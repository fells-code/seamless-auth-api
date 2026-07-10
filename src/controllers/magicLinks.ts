/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import crypto from 'crypto';
import { Request, Response } from 'express';
import { Op } from 'sequelize';

import { getSystemConfig } from '../config/getSystemConfig.js';
import { canReturnExternalDelivery } from '../lib/externalDelivery.js';
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

async function logMagicLinkFailure(req: Request, reason: string, userId?: string | null) {
  await AuthEventService.log({
    userId: userId ?? null,
    type: 'magic_link_failed',
    req,
    metadata: { reason },
  });
}

export async function requestMagicLink(req: Request, res: Response) {
  const authReq = req as AuthenticatedRequest;
  const preAuthUser = authReq.user;
  const useExternalDelivery = await canReturnExternalDelivery(req);

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
  const frontendUrl = config.frontend_url ?? config.origins[0];
  const redirect_url = `${frontendUrl}/verify-magiclink?token=${rawToken}`;

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

  const magicLinkRecord = await MagicLinkToken.create({
    user_id: user.id,
    token_hash: tokenHash,
    redirect_url,
    ip_hash,
    user_agent_hash,
    expires_at: new Date(Date.now() + TTL_MINUTES * 60 * 1000),
  });

  if (!useExternalDelivery) {
    try {
      await sendMagicLinkEmail(user.email, rawToken, redirect_url);
    } catch {
      if (magicLinkRecord.id) {
        await MagicLinkToken.update(
          { expires_at: new Date() },
          {
            where: {
              id: magicLinkRecord.id,
            },
          },
        );
      }

      await logMagicLinkFailure(req, 'Delivery failed', user.id);
      return res.status(500).json({ error: 'Failed to deliver magic link' });
    }
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
    logger.warn('No magic link found for supplied token');
    await logMagicLinkFailure(req, 'Invalid verification token');
    return res.status(400).json({ error: 'Invalid verification token' });
  }

  if (record.used_at) {
    logger.warn('Magic link token is already used');
    await logMagicLinkFailure(req, 'Token already used', record.user_id);
    return res.status(400).json({ error: 'Invalid verification token' });
  }

  if (record.expires_at < new Date()) {
    logger.warn('Magic link token expired');
    await logMagicLinkFailure(req, 'Token expired', record.user_id);
    return res.status(400).json({ error: 'Invalid verification token' });
  }

  // Atomic consume
  logger.info('Magic link being consumed');

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
    logger.error('Magic link token was not consumed');
    await logMagicLinkFailure(req, 'Failed to consume token', record.user_id);
    return res.status(500).json({ error: 'Failed to use token' });
  }

  await AuthEventService.log({
    userId: record.user_id,
    type: 'magic_link_success',
    req,
    metadata: { reason: 'Magic link token consumed' },
  });

  // Device binding is enforced at the poll step (pollMagicLinkConfirmation), where the
  // session is actually issued. A magic link may legitimately be opened on a different
  // device than the one that requested it, so verification must not gate on the device.
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
    return res.status(204).end();
  }

  // Device binding check
  const { ip_hash, user_agent_hash } = hashDeviceFingerprint(req.ip, req.headers['user-agent']);

  if (record.ip_hash && record.ip_hash !== ip_hash) {
    await logMagicLinkFailure(req, 'Polling device IP mismatch', user.id);
    return res.status(403).json({ error: 'Invalid request' });
  }

  if (record.user_agent_hash && record.user_agent_hash !== user_agent_hash) {
    await logMagicLinkFailure(req, 'Polling device user agent mismatch', user.id);
    return res.status(403).json({ error: 'Invalid request' });
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
      logger.info('Bootstrap admin granted');
    }

    await AuthEventService.log({
      userId: user.id,
      type: 'registration_success',
      req,
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
    });

    await user.update({
      lastLogin: new Date(),
      challengeContext: null,
    });

    return;
  }
  return res.status(204).end();
}
