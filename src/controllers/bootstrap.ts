/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { Request, Response } from 'express';

import {
  canReturnExternalDelivery,
  canReturnSensitiveDevelopmentDetails,
} from '../lib/externalDelivery.js';
import {
  assertBootstrapAllowed,
  assertBootstrapSecret,
  BootstrapError,
  createAdminBootstrapInvite,
} from '../services/bootstrapService.js';
import getLogger from '../utils/logger.js';

const logger = getLogger('bootstrapAdminInvite');

function getBearerToken(req: Request): string | undefined {
  const auth = req.header('authorization');
  if (!auth) return undefined;

  const [scheme, token] = auth.split(' ');
  if (scheme?.toLowerCase() !== 'bearer') return undefined;

  return token;
}

export async function createAdminBootstrapInviteHandler(req: Request, res: Response) {
  try {
    logger.info('Creating a bootstrap admin invitation');

    const bearerToken = getBearerToken(req);

    assertBootstrapSecret(bearerToken);
    await assertBootstrapAllowed();

    const { email } = req.body;
    const useExternalDelivery = await canReturnExternalDelivery(req);
    const includeSensitiveDetails =
      useExternalDelivery || canReturnSensitiveDevelopmentDetails(req);

    const result = await createAdminBootstrapInvite({
      email,
      createdIp: req.ip ?? null,
      createdUserAgent: req.get('user-agent') ?? null,
      sendMessage: !useExternalDelivery,
    });

    return res.status(201).json({
      success: true,
      data: {
        expiresAt: result.expiresAt.toISOString(),
        ...(includeSensitiveDetails
          ? {
              url: result.registrationUrl,
              token: result.token,
            }
          : {}),
        ...(useExternalDelivery
          ? {
              delivery: {
                kind: 'bootstrap_invite_email',
                to: result.email,
                inviteUrl: result.registrationUrl,
                token: result.token,
              },
            }
          : {}),
      },
    });
  } catch (error) {
    if (error instanceof BootstrapError) {
      return res.status(error.status).json({
        success: false,
        error: {
          code: error.code,
          message: error.message,
        },
      });
    }

    return res.status(500).json({
      success: false,
      error: {
        code: 'BOOTSTRAP_INTERNAL_ERROR',
        message: 'An unexpected error occurred.',
      },
    });
  }
}
