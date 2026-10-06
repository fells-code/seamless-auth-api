/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { Request, Response } from 'express';
import { Op } from 'sequelize';

import { Session } from '../models/sessions.js';
import { serializeSession } from '../services/apiResponseSerializers.js';
import { hardRevokeSession } from '../services/sessionService.js';
import { AuthenticatedRequest } from '../types/types.js';
import getLogger from '../utils/logger.js';

const logger = getLogger('sessions');

export const listSessions = async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const user = authReq.user;

  if (!user) {
    return res.status(401).json({ error: 'Not allowed' });
  }

  const now = new Date();

  // Rotation leaves the superseded row unrevoked, and an expired row is never revoked at
  // all, so filtering on revokedAt alone listed every session a refresh ever replaced.
  const sessions = await Session.findAll({
    where: {
      userId: user.id,
      revokedAt: null,
      replacedBySessionId: null,
      expiresAt: { [Op.gt]: now },
      idleExpiresAt: { [Op.gt]: now },
    },
  });

  const currentSessionId = authReq.sessionId;

  const response = sessions.map((session) => serializeSession(session, currentSessionId));

  return res.json({ sessions: response, total: response.length });
};

export const revokeSession = async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const user = authReq.user;

  if (!user) {
    return res.status(401).json({ error: 'Not allowed' });
  }

  const { id } = req.params;

  const session = await Session.findOne({
    where: { id, userId: user.id },
  });

  if (!session) {
    return res.status(404).json({ error: 'Session not found' });
  }

  await hardRevokeSession(session, 'user_revoked');

  logger.info(`Session revoked ${session.id}`);

  return res.json({ message: 'Success' });
};

export const revokeAllSessions = async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const user = authReq.user;

  if (!user) {
    return res.status(401).json({ error: 'Not allowed' });
  }

  const sessions = await Session.findAll({
    where: { userId: user.id, revokedAt: null },
  });

  for (const session of sessions) {
    await hardRevokeSession(session, 'user_logout_all');
  }

  logger.info(`All sessions revoked for user ${user.id}`);

  return res.json({ message: 'Success' });
};
