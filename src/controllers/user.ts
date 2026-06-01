/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { Request, Response } from 'express';

import { Credential } from '../models/credentials.js';
import { User } from '../models/users.js';
import { serializeCredential } from '../services/apiResponseSerializers.js';
import { AuthEventService } from '../services/authEventService.js';
import { listOrganizationsForUser } from '../services/organizationService.js';
import { AuthenticatedRequest } from '../types/types.js';
import getLogger from '../utils/logger.js';

const logger = getLogger('user');

export const getUser = async (req: Request, res: Response) => {
  logger.debug('Retrieving user');
  const authReq = req as AuthenticatedRequest;
  const authUser = authReq.user;

  try {
    if (authUser) {
      const [credentials, organizations] = await Promise.all([
        Credential.findAll({
          where: { userId: authUser.id },
          attributes: [
            'id',
            'transports',
            'deviceType',
            'backedup',
            'counter',
            'prfCapable',
            'friendlyName',
            'lastUsedAt',
            'platform',
            'browser',
            'deviceInfo',
            'createdAt',
          ],
        }),
        listOrganizationsForUser(authUser.id),
      ]);
      const activeOrganizationId = authReq.organizationId ?? null;

      return res.json({
        user: {
          id: authUser.id,
          email: authUser.email,
          phone: authUser.phone,
          roles: authUser.roles,
          lastLogin: authUser.lastLogin,
          activeOrganizationId,
        },
        credentials: credentials.map(serializeCredential),
        organizations,
        activeOrganization:
          organizations.find((organization) => organization.id === activeOrganizationId) ?? null,
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

    logger.info('Authenticated user triggered account deletion');

    try {
      const user = await User.findOne({
        where: {
          email: authUser.email.toLowerCase(),
          phone: authUser.phone,
        },
      });

      if (user) {
        logger.info('Deleting all user credentials');
        const creds = await Credential.findAll({ where: { userId: user.id } });

        creds.forEach((cred) => {
          cred.destroy();
        });

        await AuthEventService.log({
          userId: user.id || null,
          type: 'credentials_deleted',
          req,
          metadata: { reason: 'User deleted account' },
        });

        logger.info(`All credentials deleted for ${user.id}.`);

        user.destroy();
        logger.info('User deleted');

        await AuthEventService.log({
          userId: user?.id || null,
          type: 'user_deleted',
          req,
          metadata: { reason: 'User deleted account' },
        });
      } else {
        logger.error('Failed to destroy a seemingly valid user');
      }

      return res.status(200).json({ message: 'Success' });
    } catch (error: unknown) {
      logger.error(`Failed to delete user: ${error}`);
      return res.status(500).json({ message: 'Failed' });
    }
  } catch (error) {
    logger.error(`Error occured deleting a user: ${error}`);
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

    return res.json({ message: 'Credential updated', credential: serializeCredential(cred) });
  } catch (err) {
    logger.error(`Failed to update credential: ${err}`);
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
    logger.error(`Failed to delete credential: ${err}`);
    return res.status(500).json({ error: 'Failed to delete credential' });
  }
};
