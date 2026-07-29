/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { Request, Response } from 'express';
import { Op } from 'sequelize';

import { AuthEvent } from '../models/authEvents.js';
import { FAILURE_EVENT_TYPES } from '../schemas/authEvent.types.js';
import { serializeAuthEvents } from '../services/authEventSerialization.js';
import getLogger from '../utils/logger.js';

const logger = getLogger('internalSecurity');

export const getSecurityAnomalies = async (_req: Request, res: Response) => {
  const now = new Date();
  const windowStart = new Date(now.getTime() - 60 * 60 * 1000 * 24);

  try {
    // Derived from AUTH_EVENT_TYPES. The hand-maintained list searched for five names
    // nothing emitted (bearer_token_failed, jwks_failed, otp_failed,
    // recovery_otp_failed, user_data_failed) while missing verify_otp_failed,
    // totp_failed, magic_link_failed, and logout_failed, which are emitted.
    const FAILURE_TYPES = FAILURE_EVENT_TYPES;

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
    return res.status(500).json({ error: 'Failed to detect anomalies' });
  }
};
