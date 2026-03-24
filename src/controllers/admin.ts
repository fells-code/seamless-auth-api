import { CreateUserSchema } from '@seamless-auth/types';
import { Request, Response } from 'express';
import { Op } from 'sequelize';

import { AuthEvent } from '../models/authEvents.js';
import { Credential } from '../models/credentials.js';
import { sequelize } from '../models/index.js';
import { Session } from '../models/sessions.js';
import { User } from '../models/users.js';
import { hardRevokeSession } from '../services/sessionService.js';
import { ServiceRequest } from '../types/types.js';
import getLogger from '../utils/logger.js';

const logger = getLogger('admin');

export const createUser = async (req: Request, res: Response) => {
  const parsed = CreateUserSchema.safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({
      message: 'Invalid payload',
      details: parsed.error,
    });
  }

  const { email, phone, roles } = parsed.data;

  try {
    const existing = await User.findOne({ where: { email } });

    if (existing) {
      return res.status(409).json({ message: 'User already exists' });
    }

    const user = await User.create({
      email,
      phone: phone,
      roles: roles ?? [],
    });

    return res.status(201).json({ user });
  } catch (err) {
    return res.status(500).json({ message: 'Failed to create user' });
  }
};

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

export const listAllSessions = async (req: Request, res: Response) => {
  const { limit = 10, offset = 0 } = req.query;

  const [sessions, total] = await Promise.all([
    Session.findAll({
      where: { revokedAt: null },
      limit: Number(limit),
      offset: Number(offset),
    }),
    Session.count({ where: { revokedAt: null } }),
  ]);

  return res.json({ sessions, total });
};

export const getUserDetail = async (req: ServiceRequest, res: Response) => {
  const { userId } = req.params;

  const user = await User.findByPk(userId);

  if (!user) {
    return res.status(404).json({ message: 'User not found' });
  }

  const sessions = await Session.findAll({
    where: { userId },
  });

  const credentials = await Credential.findAll({
    where: { userId },
  });

  const events = await AuthEvent.findAll({
    where: { user_id: userId },
    limit: 50,
    order: [['created_at', 'DESC']],
  });

  return res.json({
    user,
    sessions,
    credentials,
    events,
  });
};

export const getUserAnomalies = async (req: Request, res: Response) => {
  const { userId } = req.params;

  try {
    const userEvents = await AuthEvent.findAll({
      where: { user_id: userId },
      attributes: ['ip_address', 'user_agent'],
    });

    const ips = [...new Set(userEvents.map((e) => e.ip_address).filter(Boolean))];
    const agents = [...new Set(userEvents.map((e) => e.user_agent).filter(Boolean))];

    const suspiciousEvents = await AuthEvent.findAll({
      where: {
        type: { [Op.like]: '%suspicious%' },
        [Op.or]: [
          { user_id: userId },
          { ip_address: { [Op.in]: ips ?? [] } },
          { user_agent: { [Op.in]: agents ?? [] } },
        ],
      },
      order: [['created_at', 'DESC']],
      limit: 50,
    });

    return res.json({
      suspiciousEvents: suspiciousEvents,
      relatedIps: Array.from(ips),
      relatedAgents: Array.from(agents),
    });
  } catch {
    return res.status(500).json({ message: 'Failed to fetch anomalies' });
  }
};

export const getDatabaseSize = async () => {
  const [result] = await sequelize.query(`
    SELECT pg_database_size(current_database()) as size
  `);

  return Number((result as any)[0].size);
};
