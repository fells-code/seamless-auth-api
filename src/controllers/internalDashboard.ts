import { Request, Response } from 'express';
import { Op } from 'sequelize';

import { AuthEvent } from '../models/authEvents.js';
import { Session } from '../models/sessions.js';
import { User } from '../models/users.js';
import { getDatabaseSize } from './admin.js';

export const getDashboardMetrics = async (_req: Request, res: Response) => {
  const now = new Date();
  const last24h = new Date(now.getTime() - 1000 * 60 * 60 * 24);

  try {
    const [
      totalUsers,
      activeSessions,
      newUsers24h,
      loginSuccess24h,
      loginFailed24h,
      otpUsage24h,
      passkeyUsage24h,
      dbSize,
    ] = await Promise.all([
      User.count(),
      Session.count({ where: { revokedAt: null } }),

      User.count({
        where: {
          createdAt: { [Op.gt]: last24h },
        },
      }),

      AuthEvent.count({
        where: {
          type: 'login_success',
          created_at: { [Op.gt]: last24h },
        },
      }),

      AuthEvent.count({
        where: {
          type: 'login_failed',
          created_at: { [Op.gt]: last24h },
        },
      }),

      AuthEvent.count({
        where: {
          type: 'otp_success',
          created_at: { [Op.gt]: last24h },
        },
      }),

      AuthEvent.count({
        where: {
          type: { [Op.like]: '%webauthn_login_success%' },
          created_at: { [Op.gt]: last24h },
        },
      }),

      getDatabaseSize(),
    ]);

    const totalLogins = loginSuccess24h + loginFailed24h;

    return res.json({
      totalUsers,
      activeSessions,
      newUsers24h,

      loginSuccess24h,
      loginFailed24h,
      successRate24h: totalLogins > 0 ? loginSuccess24h / totalLogins : 0,

      otpUsage24h,
      passkeyUsage24h,
      databaseSize: dbSize,
    });
  } catch {
    return res.status(500).json({ message: 'Failed to fetch dashboard metrics' });
  }
};
