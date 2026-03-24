import { UpdateUserSchema } from '@seamless-auth/types';
import { Response } from 'express';
import { Op } from 'sequelize';

import { AuthEvent } from '../models/authEvents.js';
import { Credential } from '../models/credentials.js';
import { User } from '../models/users.js';
import { AuthEventQuerySchema } from '../schemas/internal.query.js';
import { AuthEventService } from '../services/authEventService.js';
import { ServiceRequest } from '../types/types.js';
import getLogger from '../utils/logger.js';

const logger = getLogger('internal');

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

export const getUsers = async (req: ServiceRequest, res: Response) => {
  const { limit = 50, offset = 0, search } = req.query;

  const where: any = {};

  if (search) {
    where[Op.or] = [
      { email: { [Op.iLike]: `%${search}%` } },
      { phone: { [Op.iLike]: `%${search}%` } },
    ];
  }

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
    users: users ?? [],
    total,
  });
};

export const getAuthEvents = async (req: ServiceRequest, res: Response) => {
  const parsed = AuthEventQuerySchema.safeParse(req.query);

  if (!parsed.success) {
    return res.status(400).json({ message: 'Invalid query params' });
  }

  const { limit, offset, userId, type, from, to } = parsed.data;

  const where: any = {};

  if (type) {
    const raw = Array.isArray(type) ? req.query.type : [req.query.type];

    const expanded = raw.flatMap(expandType);

    where.type = {
      [Op.in]: expanded,
    };
  }

  if (from || to) {
    where.created_at = {};
    if (from) where.created_at[Op.gte] = new Date(from);
    if (to) where.created_at[Op.lte] = new Date(to);
  }

  if (userId) where.user_id = userId;

  if (from || to) {
    where.created_at = {};
    if (from) where.created_at[Op.gte] = new Date(from);
    if (to) where.created_at[Op.lte] = new Date(to);
  }

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

    return res.json({ events, total });
  } catch (err) {
    logger.error(`Failed to fetch auth events: ${err}`);
    res.status(500).json({ message: 'Failed to fetch events' });
  }
};

export const getCredentialsCount = async (req: ServiceRequest, res: Response) => {
  logger.info('Internal credential count call made.');
  try {
    const credentialCount = await Credential.count();

    return res.json({ count: credentialCount || 0 });
  } catch (err) {
    logger.error(`Failed to fetch credential count: ${err}`);
    res.status(500).json({ message: 'Failed to fetch credential count' });
  }
};

export const deleteUser = async (req: ServiceRequest, res: Response) => {
  logger.info('Internal deletion call made.');
  const { userId } = req.body;

  try {
    if (!userId) {
      return res.status(404).json({ message: 'User not found.' });
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
      return res.status(500).json({ message: 'Failed' });
    }
  } catch (error) {
    logger.error(`Error occured deleting a user: ${error}`);
    return res.status(500).json({ message: `Failed` });
  }
};

export const updateUser = async (req: ServiceRequest, res: Response) => {
  const { userId } = req.params;

  if (!userId) {
    logger.error('Missing user id for updating user');
    return res.status(400).json({ message: 'Bad request' });
  }

  const parsed = UpdateUserSchema.safeParse(req.body);

  if (!parsed.success || Object.keys(parsed.data).length === 0) {
    logger.error(`Failed to parse update user body. ${JSON.stringify(req.body)}`);
    return res.status(400).json({
      message: 'Invalid update payload',
      details: parsed.error,
    });
  }

  try {
    const user = await User.findByPk(userId);

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
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
      res.status(500).json({ message: 'Failed to update user' });
      return;
    }

    res.status(200).json({ user });
    return;
  } catch {
    logger.error('Failed to find user');
    res.status(400).json({ message: 'Could not update users' });
  }
};
