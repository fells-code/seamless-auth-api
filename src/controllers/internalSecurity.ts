/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { Request, Response } from 'express';
import { Op } from 'sequelize';

import { AuthEvent } from '../models/authEvents.js';
import { FAILURE_EVENT_TYPES } from '../schemas/authEvent.types.js';
import { serializeAuthEvents } from '../services/authEventSerialization.js';
import getLogger from '../utils/logger.js';
import { resolveMetricsWindow } from './internalDashboard.js';

const logger = getLogger('internalSecurity');

/**
 * Rows one call will return.
 *
 * Bounded because the matched set is attacker-controlled: `request_suspicious` is
 * recorded for every unmatched route and every refused origin, so a scanner alone can
 * make a day's window arbitrarily large.
 */
const ANOMALY_LIMIT = 200;

export const getSecurityAnomalies = async (req: Request, res: Response) => {
  const { limit = ANOMALY_LIMIT, offset = 0 } = req.query as unknown as {
    limit?: number;
    offset?: number;
  };
  const { start, end } = resolveMetricsWindow(req.query as { from?: string; to?: string });

  try {
    // Derived from AUTH_EVENT_TYPES. The hand-maintained list searched for five names
    // nothing emitted (jwks_failed, otp_failed, recovery_otp_failed, user_data_failed,
    // and bearer_token_failed, which the auth gate now does emit) while missing
    // verify_otp_failed, totp_failed, magic_link_failed, and logout_failed.
    const FAILURE_TYPES = FAILURE_EVENT_TYPES;

    const { rows, count } = await AuthEvent.findAndCountAll({
      where: {
        created_at: { [Op.gte]: start, [Op.lt]: end },
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
      order: [['created_at', 'DESC']],
      limit,
      offset,
    });

    return res.json({
      suspiciousEvents: serializeAuthEvents(rows),
      // Every match in the window, not the page size, so a caller can tell there is more.
      total: count,
      window: { from: start.toISOString(), to: end.toISOString() },
      limit,
      offset,
    });
  } catch {
    logger.error(`Failed to get security events`);
    return res.status(500).json({ error: 'Failed to detect anomalies' });
  }
};
