/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { Request, Response } from 'express';
import { Op } from 'sequelize';

import { AuthEvent } from '../models/authEvents.js';
import { serializeAuthEvents } from '../services/authEventSerialization.js';
import getLogger from '../utils/logger.js';

const logger = getLogger('internalSecurity');

export const getSecurityAnomalies = async (_req: Request, res: Response) => {
  const now = new Date();
  const windowStart = new Date(now.getTime() - 60 * 60 * 1000 * 24);

  try {
    const FAILURE_TYPES = [
      'login_failed',
      'bearer_token_failed',
      'jwks_failed',
      'mfa_otp_failed',
      'otp_failed',
      'recovery_otp_failed',
      'refresh_token_failed',
      'registration_failed',
      'service_token_failed',
      'user_data_failed',
      'webauthn_login_failed',
      'webauthn_registration_failed',
    ];

    const events = await AuthEvent.findAll({
      where: {
        created_at: {
          [Op.gte]: windowStart,
        },
        [Op.or]: [
          {
            type: {
              [Op.in]: FAILURE_TYPES,
            },
          },
          {
            type: {
              [Op.like]: '%suspicious%',
            },
          },
        ],
      },
      attributes: ['user_id', 'type', 'ip_address', 'user_agent', 'metadata', 'created_at'],
    });

    return res.json({
      suspiciousEvents: serializeAuthEvents(events),
      total: events.length,
    });
  } catch {
    logger.error(`Failed to get security events`);
    return res.status(500).json({ message: 'Failed to detect anomalies' });
  }
};
