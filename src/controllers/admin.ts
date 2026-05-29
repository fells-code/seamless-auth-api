/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { Request, Response } from 'express';
import { Op, WhereOptions } from 'sequelize';

import { AuthEvent, AuthEventAttributes } from '../models/authEvents.js';
import { Credential } from '../models/credentials.js';
import { getSequelize } from '../models/index.js';
import { Session } from '../models/sessions.js';
import { TotpCredential } from '../models/totpCredentials.js';
import { User } from '../models/users.js';
import {
  CreateUserSchema,
  DeviceReplacementRecoverySchema,
  UpdateUserSchema,
} from '../schemas/admin.requests.js';
import { AuthEventQuerySchema } from '../schemas/internal.query.js';
import {
  serializeApiUser,
  serializeCredential,
  serializeSession,
} from '../services/apiResponseSerializers.js';
import { serializeAuthEvents } from '../services/authEventSerialization.js';
import { AuthEventService } from '../services/authEventService.js';
import { hardRevokeSession } from '../services/sessionService.js';
import { ServiceRequest } from '../types/types.js';
import getLogger from '../utils/logger.js';
import { redactMetadata } from '../utils/redaction.js';

const logger = getLogger('admin');

export const getUsers = async (req: ServiceRequest, res: Response) => {
  const { limit = 50, offset = 0, search } = req.query;

  const where: WhereOptions<User> = search
    ? {
        [Op.or]: [
          { email: { [Op.iLike]: `%${search}%` } },
          { phone: { [Op.iLike]: `%${search}%` } },
        ],
      }
    : {};

  const [users, total] = await Promise.all([
    await User.findAll({
      where,
      attributes: [
        'id',
        'email',
        'phone',
        'revoked',
        'emailVerified',
        'phoneVerified',
        'verified',
        'lastLogin',
        'roles',
        'createdAt',
        'updatedAt',
      ],
      limit: Number(limit),
      offset: Number(offset),
    }),
    User.count({ where }),
  ]);

  return res.json({
    users: (users ?? []).map(serializeApiUser),
    total,
  });
};

export const createUser = async (req: Request, res: Response) => {
  const parsed = CreateUserSchema.safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({
      error: 'Invalid payload',
      details: parsed.error,
    });
  }

  const { email, phone, roles } = parsed.data;

  try {
    const existing = await User.findOne({ where: { email } });

    if (existing) {
      return res.status(409).json({ error: 'User already exists' });
    }

    const user = await User.create({
      email,
      phone: phone,
      roles: roles ?? [],
    });

    return res.status(201).json({ user: serializeApiUser(user) });
  } catch (err) {
    logger.error(`Failed to create user. Reason: ${err}`);
    return res.status(500).json({ error: 'Failed to create user' });
  }
};

export const deleteUser = async (req: ServiceRequest, res: Response) => {
  logger.info('Internal deletion call made.');
  const { userId } = req.body;

  try {
    if (!userId) {
      return res.status(404).json({ error: 'User not found.' });
    }

    try {
      const user = await User.findOne({
        where: {
          id: userId,
        },
      });

      if (user) {
        user.destroy();
        logger.info(`User ${user.email} deleted from database through the seamless auth portal.`);
      } else {
        logger.error(`Failed to destory a seemingly valid user via the portal`);
      }

      return res.status(200).json({ message: 'Success' });
    } catch (error: unknown) {
      logger.error(`Failed to delete user: ${userId}. Error: ${error}`);
      return res.status(500).json({ error: 'Failed' });
    }
  } catch (error) {
    logger.error(`Error occured deleting a user: ${error}`);
    return res.status(500).json({ error: `Failed` });
  }
};

export const updateUser = async (req: ServiceRequest, res: Response) => {
  const { userId } = req.params;

  if (!userId) {
    logger.error('Missing user id for updating user');
    return res.status(400).json({ error: 'Bad request' });
  }

  const parsed = UpdateUserSchema.safeParse(req.body);

  if (!parsed.success || Object.keys(parsed.data).length === 0) {
    logger.error(`Failed to parse update user body. ${JSON.stringify(redactMetadata(req.body))}`);
    return res.status(400).json({
      error: 'Invalid update payload',
      details: parsed.error,
    });
  }

  try {
    const user = await User.findByPk(userId);

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const before = user.toJSON();

    try {
      await user.update(parsed.data);

      await AuthEventService.log({
        type: 'internal_user_updated_by_owner',
        req,
        metadata: {
          before,
          after: parsed.data,
          targetUser: userId,
        },
      });
    } catch (error) {
      logger.error(`Failed to update user ${error}`);
      res.status(500).json({ error: 'Failed to update user' });
      return;
    }

    res.status(200).json({ user: serializeApiUser(user) });
    return;
  } catch {
    logger.error('Failed to find user');
    res.status(400).json({ error: 'Could not update users' });
  }
};

export const getUserDetail = async (req: ServiceRequest, res: Response) => {
  const { userId } = req.params;

  const user = await User.findByPk(userId);

  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  const now = new Date();

  const sessions = await Session.findAll({
    where: {
      userId,
      revokedAt: null,
      replacedBySessionId: null,
      expiresAt: {
        [Op.gt]: now,
      },
    },
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
    user: serializeApiUser(user),
    sessions: sessions.map((session) => serializeSession(session)),
    credentials: credentials.map(serializeCredential),
    events: serializeAuthEvents(events),
  });
};

export const getUserAnomalies = async (req: Request, res: Response) => {
  const { userId } = req.params;

  try {
    const userEvents = await AuthEvent.findAll({
      where: { user_id: userId },
      attributes: ['ip_address', 'user_agent'],
    });

    const ips = [...new Set(userEvents.map((e) => e.ip_address).filter((v): v is string => !!v))];

    const agents = [
      ...new Set(userEvents.map((e) => e.user_agent).filter((v): v is string => !!v)),
    ];

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
      suspiciousEvents: serializeAuthEvents(suspiciousEvents),
      relatedIps: Array.from(ips),
      relatedAgents: Array.from(agents),
    });
  } catch {
    return res.status(500).json({ error: 'Failed to fetch anomalies' });
  }
};

// TODO: Need a public session return type for sessions
export const listUserSessions = async (req: Request, res: Response) => {
  const { userId } = req.params;

  const now = new Date();

  try {
    const sessions = await Session.findAll({
      where: {
        userId,
        revokedAt: null,
        replacedBySessionId: null,
        expiresAt: {
          [Op.gt]: now,
        },
      },
    });

    return res.json({
      sessions: sessions.map((session) => serializeSession(session)),
      total: sessions.length,
    });
  } catch (err) {
    logger.error(`Failed to fetch sessions: ${err}`);
    return res.status(500).json({ error: 'Failed to fetch sessions' });
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
    return res.status(500).json({ error: 'Failed to revoke sessions' });
  }
};

export const revokeUserSessionById = async (req: Request, res: Response) => {
  const { id } = req.params;

  try {
    const session = await Session.findOne({
      where: {
        id,
        revokedAt: null,
      },
    });

    if (!session) {
      return res.status(404).json({ error: 'Session not found' });
    }

    await hardRevokeSession(session, 'admin_revoke');

    await AuthEventService.log({
      userId: session.userId,
      type: 'admin_session_revoked',
      req,
      metadata: {
        targetUser: session.userId,
        sessionId: session.id,
      },
    });

    return res.json({ message: 'Success' });
  } catch (err) {
    logger.error(`Failed to revoke session: ${err}`);
    return res.status(500).json({ error: 'Failed to revoke session' });
  }
};

export const recoverUserForDeviceReplacement = async (req: Request, res: Response) => {
  const { userId } = req.params;
  const parsed = DeviceReplacementRecoverySchema.safeParse(req.body ?? {});

  if (!parsed.success) {
    return res.status(400).json({
      error: 'Invalid recovery payload',
      details: parsed.error,
    });
  }

  const user = await User.findByPk(userId);

  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  const { revokeSessions, removePasskeys, disableTotp } = parsed.data;
  let revokedSessions = 0;
  let removedCredentials = 0;
  let disabledTotpCredentials = 0;

  if (revokeSessions) {
    const sessions = await Session.findAll({
      where: {
        userId,
        revokedAt: null,
      },
    });

    for (const session of sessions) {
      await hardRevokeSession(session, 'admin_device_replacement');
    }

    revokedSessions = sessions.length;
  }

  if (removePasskeys) {
    const credentials = await Credential.findAll({ where: { userId } });

    for (const credential of credentials) {
      await credential.destroy();
    }

    removedCredentials = credentials.length;
  }

  if (disableTotp) {
    const [count] = await TotpCredential.update(
      { enabled: false },
      {
        where: {
          userId,
          enabled: true,
        },
      },
    );

    disabledTotpCredentials = count;
  }

  await AuthEventService.log({
    userId,
    type: 'admin_device_replacement_recovery',
    req,
    metadata: {
      targetUser: userId,
      actions: {
        revokeSessions,
        removePasskeys,
        disableTotp,
      },
      revokedSessions,
      removedCredentials,
      disabledTotpCredentials,
    },
  });

  return res.json({
    userId,
    revokedSessions,
    removedCredentials,
    disabledTotpCredentials,
  });
};

// TODO: Need a public session return type for sessions
export const listAllSessions = async (req: Request, res: Response) => {
  const { limit = 10, offset = 0 } = req.query;

  const now = new Date();

  const where = {
    revokedAt: null,
    replacedBySessionId: null,
    expiresAt: {
      [Op.gt]: now,
    },
  };

  const [sessions, total] = await Promise.all([
    Session.findAll({
      where: where,
      limit: Number(limit),
      offset: Number(offset),
    }),
    Session.count({ where }),
  ]);

  const response = sessions.map((session) => serializeSession(session));

  return res.json({ sessions: response, total });
};

export const getDatabaseSize = async () => {
  const [result] = await getSequelize().query(`
    SELECT pg_database_size(current_database()) as size
  `);

  // TODO: Properly type this one day
  return Number((result as { size: string }[])[0].size);
};

function expandType(type?: string): string[] {
  if (!type) return [];

  if (type === 'login') return ['login_success', 'login_failed'];
  if (type === 'otp') return ['otp_success', 'otp_failed'];
  if (type === 'webauthn') return ['webauthn_login_success', 'webauthn_login_failed'];
  if (type === 'magicLink') return ['magic_link_success', 'magic_link_requested'];

  if (type === 'suspicious')
    return [
      'login_suspicious',
      'otp_suspicious',
      'webauthn_login_suspicious',
      'verify_otp_suspicious',
      'service_token_suspicious',
    ];

  return [type];
}

export const getAuthEvents = async (req: ServiceRequest, res: Response) => {
  const parsed = AuthEventQuerySchema.safeParse(req.query);

  if (!parsed.success) {
    return res.status(400).json({ error: 'Invalid query params' });
  }

  const { limit, offset, userId, type, from, to } = parsed.data;

  const where: WhereOptions<AuthEventAttributes> = {};

  if (type) {
    const rawType = req.query.type;
    const raw: string[] = Array.isArray(rawType)
      ? rawType.filter((v): v is string => typeof v === 'string')
      : typeof rawType === 'string'
        ? [rawType]
        : [];

    const expanded = raw.flatMap(expandType);

    where.type = {
      [Op.in]: expanded,
    };
  }

  if (from || to) {
    where.created_at = {
      ...(from ? { [Op.gte]: new Date(from) } : {}),
      ...(to ? { [Op.lte]: new Date(to) } : {}),
    };
  }

  if (userId) where.user_id = userId;

  try {
    const [events, total] = await Promise.all([
      AuthEvent.findAll({
        where,
        order: [['created_at', 'DESC']],
        limit,
        offset,
      }),
      AuthEvent.count({
        where,
      }),
    ]);

    return res.json({ events: serializeAuthEvents(events), total });
  } catch (err) {
    logger.error(`Failed to fetch auth events: ${err}`);
    res.status(500).json({ error: 'Failed to fetch events' });
  }
};

export const getCredentialsCount = async (req: ServiceRequest, res: Response) => {
  logger.info('Internal credential count call made.');
  try {
    const credentialCount = await Credential.count();

    return res.json({ count: credentialCount || 0 });
  } catch (err) {
    logger.error(`Failed to fetch credential count: ${err}`);
    res.status(500).json({ error: 'Failed to fetch credential count' });
  }
};
