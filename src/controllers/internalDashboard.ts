import { Request, Response } from 'express';

import { AuthEvent } from '../models/authEvents.js';
import { Session } from '../models/sessions.js';
import { User } from '../models/users.js';

export const getDashboardMetrics = async (_req: Request, res: Response) => {
  try {
    const [totalUsers, totalSessions, loginSuccess, loginFailed] = await Promise.all([
      User.count(),
      Session.count({ where: { revokedAt: null } }),
      AuthEvent.count({ where: { type: 'login_success' } }),
      AuthEvent.count({ where: { type: 'login_failed' } }),
    ]);

    return res.json({
      users: totalUsers,
      activeSessions: totalSessions,
      loginSuccess,
      loginFailed,
      successRate: loginSuccess + loginFailed > 0 ? loginSuccess / (loginSuccess + loginFailed) : 0,
    });
  } catch {
    return res.status(500).json({ message: 'Failed to fetch dashboard metrics' });
  }
};
