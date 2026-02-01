/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import { Request, Response } from 'express';

import { clearAuthCookies } from '../lib/cookie';
import { AuthEvent } from '../models/authEvents';
import { Credential } from '../models/credentials';
import { User } from '../models/users';
import { AuthEventService } from '../services/authEventService';
import { AuthenticatedRequest } from '../types/types';
import getLogger from '../utils/logger';

const logger = getLogger('user');

export const getUser = async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const authUser = authReq.user;

  try {
    if (authUser) {
      const credentials = await Credential.findAll({
        where: { userId: authUser.id },
        attributes: [
          'id',
          'transports',
          'deviceType',
          'backedup',
          'counter',
          'friendlyName',
          'lastUsedAt',
          'platform',
          'browser',
          'deviceInfo',
          'createdAt',
        ],
      });

      return res.json({
        user: {
          id: authUser.id,
          email: authUser.email,
          phone: authUser.phone,
          roles: authUser.roles,
          lastLogin: authUser.lastLogin,
        },
        credentials,
      });
    } else {
      return res.status(404).json({ message: 'User not found' });
    }
  } catch (error) {
    logger.error(`Error occured getting user: ${error}`);
    await AuthEventService.log({
      userId: null,
      type: 'user_data_suspicious',
      req,
      metadata: { reason: 'Error occured' },
    });
    clearAuthCookies(res);
    res.status(500).json({ message: 'Internal server error' });
    return;
  }
};

export const deleteUser = async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const authUser = authReq.user;

  try {
    if (!authUser) {
      return res.status(404).json({ message: 'User not found.' });
    }

    logger.info(`${authUser.email} trigger the deletion of their account`);
    clearAuthCookies(res);

    try {
      const user = await User.findOne({
        where: {
          email: authUser.email.toLowerCase(),
          phone: authUser.phone,
        },
      });

      if (user) {
        logger.info(`Deleting all users credentials for ${user.email}.`);
        const creds = await Credential.findAll({ where: { userId: user.id } });

        creds.forEach((cred) => {
          cred.destroy();
        });

        await AuthEvent.create({
          user_id: user.id || null,
          type: 'credentials_deleted',
          ip_address: req.ip,
          user_agent: req.headers['user-agent'],
          metadata: { reason: 'User deleted account' },
        });

        logger.info(`All credentials deleted for ${user.id}.`);

        user.destroy();
        logger.info(`User ${user.email} deleted.`);

        await AuthEvent.create({
          user_id: user?.id || null,
          type: 'user_deleted',
          ip_address: req.ip,
          user_agent: req.headers['user-agent'],
          metadata: { reason: 'User deleted account' },
        });
      } else {
        logger.error(`Failed to destory a seemingly valid user ${authUser.email}`);
      }

      return res.status(200).json({ message: 'Success' });
    } catch (error: unknown) {
      logger.error(`Failed to delete user: ${authUser.email}${error}`);
      return res.status(500).json({ message: 'Failed' });
    }
  } catch (error) {
    logger.error(`Error occured deleting a user: ${error}`);
    try {
      clearAuthCookies(res);
      return res.json({ message: 'Success' });
    } catch (error) {
      logger.error(`Couldn't delete all cookies. ${error}`);
    }

    return res.status(500).json({ message: `Failed` });
  }
};

export const updateCredential = async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const authUser = authReq.user;

  if (!authUser) return res.status(401).json({ error: 'Unauthorized' });

  const { friendlyName, id } = req.body;

  try {
    const cred = await Credential.findOne({
      where: {
        id,
        userId: authUser.id,
      },
    });

    if (!cred) {
      return res.status(404).json({ error: 'Credential not found' });
    }

    await cred.update({
      friendlyName: friendlyName ?? cred.friendlyName,
    });

    return res.json({ message: 'Credential updated', credential: cred });
  } catch (err) {
    logger.error(err);
    return res.status(500).json({ error: 'Failed to update credential' });
  }
};

export const deleteCredential = async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const authUser = authReq.user;

  if (!authUser) return res.status(401).json({ error: 'Unauthorized' });

  const { id } = req.body;

  try {
    const cred = await Credential.findOne({
      where: {
        id,
        userId: authUser.id,
      },
    });

    if (!cred) {
      return res.status(404).json({ error: 'Credential not found' });
    }

    const count = await Credential.count({ where: { userId: authUser.id } });

    if (count <= 1) {
      return res.status(400).json({
        error: 'You must keep at least one credential.',
      });
    }

    await cred.destroy();

    return res.json({ message: 'Credential deleted' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Failed to delete credential' });
  }
};
