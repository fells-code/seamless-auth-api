/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { Request, Response } from 'express';

import {
  assertBootstrapAllowed,
  assertBootstrapSecret,
  BootstrapError,
  createAdminBootstrapInvite,
} from '../services/bootstrapService.js';

function getBearerToken(req: Request): string | undefined {
  const auth = req.header('authorization');
  if (!auth) return undefined;

  const [scheme, token] = auth.split(' ');
  if (scheme?.toLowerCase() !== 'bearer') return undefined;

  return token;
}

export async function createAdminBootstrapInviteHandler(req: Request, res: Response) {
  try {
    const bearerToken = getBearerToken(req);

    assertBootstrapSecret(bearerToken);
    await assertBootstrapAllowed();

    const { email } = req.body;

    const result = await createAdminBootstrapInvite({
      email,
      createdIp: req.ip ?? null,
      createdUserAgent: req.get('user-agent') ?? null,
    });

    return res.status(201).json({
      success: true,
      data: {
        url: result.registrationUrl,
        expiresAt: result.expiresAt.toISOString(),
        token: result.token,
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
