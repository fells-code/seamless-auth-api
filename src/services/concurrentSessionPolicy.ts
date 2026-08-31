/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { Request } from 'express';
import { Op } from 'sequelize';

import { Session } from '../models/sessions.js';
import getLogger from '../utils/logger.js';
import { AuthEventService } from './authEventService.js';

const logger = getLogger('concurrentSessionPolicy');

/** The reason written to `sessions.revokedReason`, so an audit can tell why it ended. */
export const EVICTION_REASON = 'concurrent_session_limit';

/**
 * Makes room for one more session by revoking the oldest, when a user is at the
 * configured limit.
 *
 * Called before the new session is created, so the limit counts what will exist
 * once it is: at a limit of 3, a user holding 3 loses their oldest and ends up
 * with 3 again rather than 4.
 *
 * Revoking rather than refusing is deliberate. A refusal locks a user out of the
 * device in front of them until something they may not have access to expires,
 * which for a shared workstation is the common case rather than the edge one.
 *
 * More than one may be revoked in a pass: a deployment that lowers the limit
 * leaves users above it, and they should converge on the next sign-in rather
 * than one session per login forever.
 *
 * Never throws. A session that could not be revoked is logged and the sign-in
 * continues, because failing an authentication over a housekeeping step is worse
 * than briefly exceeding the cap.
 */
export async function enforceConcurrentSessionLimit(params: {
  userId: string;
  limit: number | null | undefined;
  req: Request;
  now?: Date;
}): Promise<number> {
  const { userId, limit, req } = params;

  if (!limit || limit < 1) {
    return 0;
  }

  const now = params.now ?? new Date();

  try {
    const active = await Session.findAll({
      where: {
        userId,
        revokedAt: null,
        replacedBySessionId: null,
        expiresAt: { [Op.gt]: now },
      },
      order: [['createdAt', 'ASC']],
    });

    // The incoming session is not stored yet, so the limit is compared against
    // what is already there plus the one about to be added.
    const surplus = active.length + 1 - limit;

    if (surplus < 1) {
      return 0;
    }

    const evicted = active.slice(0, surplus);

    for (const session of evicted) {
      await session.update({ revokedAt: now, revokedReason: EVICTION_REASON });

      await AuthEventService.log({
        userId,
        type: 'session_evicted',
        req,
        metadata: {
          reason: 'Concurrent session limit reached',
          sessionId: session.id,
          limit,
          activeBefore: active.length,
        },
      });
    }

    logger.info(`Evicted ${evicted.length} session(s) to stay within the limit of ${limit}.`);

    return evicted.length;
  } catch (error) {
    logger.error(`Could not enforce the concurrent session limit: ${error}`);
    return 0;
  }
}
