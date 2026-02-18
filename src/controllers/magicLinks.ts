/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import crypto from 'crypto';
import { Request, Response } from 'express';

import { getSystemConfig } from '../config/getSystemConfig';
import { MagicLinkToken } from '../models/magicLinks';
import { User } from '../models/users';
import { MagicLinkRequestSchema, MagicLinkVerifyQuerySchema } from '../schemas/magicLink.schema';
import { AuthEventService } from '../services/authEventService';
import { sendMagicLinkEmail } from '../services/messagingService';
import { hashDeviceFingerprint, hashSha256, validateRedirectUrl } from '../utils/utils';

const TTL_MINUTES = 15;

export async function requestMagicLink(req: Request, res: Response) {
  const parse = MagicLinkRequestSchema.safeParse(req.body);

  if (!parse.success) {
    return res.status(400).json({ error: 'Invalid request' });
  }

  const { email, redirect_url } = parse.data;

  const user = await User.findOne({ where: { email } });

  if (!user) {
    return res.json({
      message: 'If an account exists, a login link has been sent.',
    });
  }

  const config = await getSystemConfig();

  const safeRedirect = validateRedirectUrl(redirect_url, config.origins);

  const rawToken = crypto.randomBytes(32).toString('base64url');
  const tokenHash = hashSha256(rawToken);

  const { ip_hash, user_agent_hash } = hashDeviceFingerprint(req.ip, req.headers['user-agent']);

  await MagicLinkToken.create({
    user_id: user.id,
    token_hash: tokenHash,
    redirect_url: safeRedirect,
    ip_hash,
    user_agent_hash,
    expires_at: new Date(Date.now() + TTL_MINUTES * 60 * 1000),
  });

  await sendMagicLinkEmail(user.email, rawToken);

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
  const parse = MagicLinkVerifyQuerySchema.safeParse(req.query);

  if (!parse.success) {
    return res.redirect('/login?error=invalid');
  }

  const { token } = parse.data;
  const tokenHash = hashSha256(token);

  const record = await MagicLinkToken.findOne({
    where: { token_hash: tokenHash },
  });

  if (!record) {
    return res.redirect('/login?error=invalid');
  }

  if (record.used_at) {
    return res.redirect('/login?error=used');
  }

  if (record.expires_at < new Date()) {
    return res.redirect('/login?error=expired');
  }

  // Device binding check
  const { ip_hash, user_agent_hash } = hashDeviceFingerprint(req.ip, req.headers['user-agent']);

  if (record.ip_hash && record.ip_hash !== ip_hash) {
    return res.redirect('/login?error=device_mismatch');
  }

  if (record.user_agent_hash && record.user_agent_hash !== user_agent_hash) {
    return res.redirect('/login?error=device_mismatch');
  }

  // Atomic consume
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
    return res.redirect('/login?error=invalid');
  }

  await AuthEventService.log({
    userId: record.user_id,
    type: 'magic_link_success',
    req,
  });

  return res.redirect(record.redirect_url || '/');
}
