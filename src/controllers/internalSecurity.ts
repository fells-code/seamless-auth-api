import { Request, Response } from 'express';
import { Op } from 'sequelize';

import { AuthEvent } from '../models/authEvents.js';

export const getSecurityAnomalies = async (_req: Request, res: Response) => {
  const now = new Date();
  const windowStart = new Date(now.getTime() - 60 * 60 * 1000);

  try {
    const failedLogins = await AuthEvent.findAll({
      where: {
        type: 'login_failed',
        created_at: { [Op.gte]: windowStart },
      },
      attributes: ['ip_address'],
    });

    const ipCounts: Record<string, number> = {};

    for (const event of failedLogins) {
      const ip = event.ip_address || 'unknown';
      ipCounts[ip] = (ipCounts[ip] || 0) + 1;
    }

    const suspicious = Object.entries(ipCounts)
      .filter(([_, count]) => count > 10)
      .map(([ip, count]) => ({ ip, count }));

    return res.json({
      suspiciousIps: suspicious,
      totalFailedLogins: failedLogins.length,
    });
  } catch {
    return res.status(500).json({ message: 'Failed to detect anomalies' });
  }
};
