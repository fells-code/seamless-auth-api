/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import crypto from 'crypto';
import { literal, Op } from 'sequelize';

import { getSystemConfig } from '../config/getSystemConfig.js';
import { BootstrapInvite } from '../models/bootstrapInvites.js';
import { User } from '../models/users.js';
import getLogger from '../utils/logger.js';
import { sendBootstrapEmail } from './messagingService.js';

const logger = getLogger('adminBootstrapService');

export class BootstrapError extends Error {
  code: string;
  status: number;

  constructor(code: string, message: string, status = 400) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

export function isBootstrapEnabled(): boolean {
  return process.env.SEAMLESS_BOOTSTRAP_ENABLED === 'true';
}

export function getBootstrapSecret(): string {
  const secret = process.env.SEAMLESS_BOOTSTRAP_SECRET;
  if (!secret) {
    throw new BootstrapError(
      'BOOTSTRAP_SECRET_MISSING',
      'Bootstrap secret is not configured.',
      500,
    );
  }
  return secret;
}

export function assertBootstrapSecret(provided: string | undefined): void {
  if (!provided) {
    logger.error('Nothing provided for bootstrap secret');
    throw new BootstrapError('BOOTSTRAP_UNAUTHORIZED', 'Unauthorized.', 401);
  }

  const expected = getBootstrapSecret();

  const providedBuf = Buffer.from(provided);
  const expectedBuf = Buffer.from(expected);

  if (
    providedBuf.length !== expectedBuf.length ||
    !crypto.timingSafeEqual(providedBuf, expectedBuf)
  ) {
    logger.error('Incorrect bootstrap secret');
    throw new BootstrapError('BOOTSTRAP_UNAUTHORIZED', 'Unauthorized.', 401);
  }
}

export async function assertBootstrapAllowed(): Promise<void> {
  if (!isBootstrapEnabled()) {
    throw new BootstrapError('BOOTSTRAP_DISABLED', 'Bootstrap flow is disabled.', 403);
  }

  const adminCount = await User.count({
    where: literal(`"roles" && ARRAY['admin','admin:write']::varchar[]`),
  });

  if (adminCount > 0) {
    throw new BootstrapError(
      'BOOTSTRAP_ALREADY_COMPLETED',
      'Bootstrap flow is no longer available.',
      410,
    );
  }
}

function generateRawToken(): string {
  return crypto.randomBytes(32).toString('hex');
}

function hashToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

export async function createAdminBootstrapInvite(params: {
  email: string;
  createdIp?: string | null;
  createdUserAgent?: string | null;
  sendMessage?: boolean;
}) {
  await assertBootstrapAllowed();

  const existing = await BootstrapInvite.findOne({
    where: {
      email: params.email,
      consumedAt: null,
      expiresAt: {
        [Op.gt]: new Date(),
      },
    },
    order: [['createdAt', 'DESC']],
  });

  if (existing) {
    throw new BootstrapError(
      'BOOTSTRAP_INVITE_ALREADY_EXISTS',
      'An active bootstrap invite already exists for this email.',
      409,
    );
  }

  const rawToken = generateRawToken();
  const tokenHash = hashToken(rawToken);
  const expiresAt = new Date(Date.now() + 15 * 60 * 1000);

  await BootstrapInvite.create({
    email: params.email.toLowerCase(),
    role: 'admin',
    tokenHash,
    expiresAt,
    consumedAt: null,
    createdBy: 'bootstrap',
    createdIp: params.createdIp ?? null,
    createdUserAgent: params.createdUserAgent ?? null,
    lastSentAt: new Date(),
    attemptCount: 0,
  });

  const { origins } = await getSystemConfig();

  const registrationUrl = `${origins[0]}/login?bootstrapToken=${rawToken}`;
  if (process.env.NODE_ENV === 'development') {
    logger.info('invite link: ', registrationUrl);
  }

  if (params.sendMessage !== false) {
    await sendBootstrapEmail(params.email, registrationUrl);
  }

  return {
    email: params.email.toLowerCase(),
    registrationUrl,
    token: rawToken,
    expiresAt,
  };
}

export function hashBootstrapToken(token: string): string {
  return hashToken(token);
}
