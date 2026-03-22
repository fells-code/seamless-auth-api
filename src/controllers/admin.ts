import { Request, Response } from 'express';

import { Session } from '../models/sessions.js';
import { hardRevokeSession } from '../services/sessionService.js';
import getLogger from '../utils/logger.js';

const logger = getLogger('admin-sessions');

/*
GET /admin/sessions/:userId
*/
export const listUserSessions = async (req: Request, res: Response) => {
  const { userId } = req.params;

  try {
    const sessions = await Session.findAll({
      where: {
        userId,
        revokedAt: null,
      },
    });

    return res.json({
      sessions: sessions.map((s) => ({
        id: s.id,
        deviceName: s.deviceName,
        ipAddress: s.ipAddress,
        userAgent: s.userAgent,
        lastUsedAt: s.lastUsedAt,
        expiresAt: s.expiresAt,
      })),
    });
  } catch (err) {
    logger.error(`Failed to fetch sessions: ${err}`);
    return res.status(500).json({ message: 'Failed to fetch sessions' });
  }
};

/*
DELETE /admin/sessions/:userId/revoke-all
*/
export const revokeAllUserSessions = async (req: Request, res: Response) => {
  const { userId } = req.params;

  try {
    const sessions = await Session.findAll({
      where: {
        userId,
        revokedAt: null,
      },
    });

    for (const session of sessions) {
      await hardRevokeSession(session, 'admin_revoke_all');
    }

    logger.info(`All sessions revoked for user ${userId}`);

    return res.json({ message: 'Success' });
  } catch (err) {
    logger.error(`Failed to revoke sessions: ${err}`);
    return res.status(500).json({ message: 'Failed to revoke sessions' });
  }
};
