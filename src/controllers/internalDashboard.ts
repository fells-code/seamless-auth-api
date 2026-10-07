/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { Request, Response } from 'express';
import { Op } from 'sequelize';

import { AuthEvent } from '../models/authEvents.js';
import { Session } from '../models/sessions.js';
import { User } from '../models/users.js';
import { SIGN_IN_FAILURE_TYPES, SIGN_IN_SUCCESS_TYPES } from '../schemas/authEvent.types.js';
import { getDatabaseSize } from './admin.js';

const DAY_MS = 1000 * 60 * 60 * 24;

/**
 * `from`/`to` as a half-open window, defaulting to the 24 hours before now, which is the
 * window every caller got before the endpoints took a range.
 */
export function resolveMetricsWindow(query: { from?: string; to?: string }, now = new Date()) {
  const end = query.to ? new Date(query.to) : now;
  const start = query.from ? new Date(query.from) : new Date(end.getTime() - DAY_MS);
  return { start, end };
}

async function windowCounts(start: Date, end: Date) {
  const between = { [Op.gte]: start, [Op.lt]: end };

  const [newUsers, loginSuccess, loginFailed, otpUsage, passkeyUsage] = await Promise.all([
    User.count({ where: { createdAt: between } }),

    // Completed sign-ins. login_success is the pre-auth step resolving which methods
    // an identifier may use, so a rate built from it measures identifier resolution.
    AuthEvent.count({
      where: { type: { [Op.in]: [...SIGN_IN_SUCCESS_TYPES] }, created_at: between },
    }),
    AuthEvent.count({
      where: { type: { [Op.in]: [...SIGN_IN_FAILURE_TYPES] }, created_at: between },
    }),
    AuthEvent.count({ where: { type: 'otp_success', created_at: between } }),
    AuthEvent.count({ where: { type: 'webauthn_login_success', created_at: between } }),
  ]);

  const totalLogins = loginSuccess + loginFailed;

  return {
    newUsers,
    loginSuccess,
    loginFailed,
    successRate: totalLogins > 0 ? loginSuccess / totalLogins : 0,
    otpUsage,
    passkeyUsage,
  };
}

export const getDashboardMetrics = async (req: Request, res: Response) => {
  const now = new Date();
  const ranged = typeof req.query.from === 'string' || typeof req.query.to === 'string';
  const window = resolveMetricsWindow(req.query as { from?: string; to?: string }, now);

  try {
    const [totalUsers, activeSessions, last24h, requested, dbSize] = await Promise.all([
      User.count(),
      // The same three conditions every other 'active session' query uses. Rotation
      // leaves the superseded row unrevoked, so filtering on revokedAt alone counted
      // every session a user had ever refreshed into existence.
      Session.count({
        where: {
          revokedAt: null,
          replacedBySessionId: null,
          expiresAt: { [Op.gt]: now },
        },
      }),
      windowCounts(new Date(now.getTime() - DAY_MS), now),
      // Without a range the requested window is the last 24 hours, already counted.
      ranged ? windowCounts(window.start, window.end) : null,
      getDatabaseSize(),
    ]);

    // The *24h fields keep meaning the last 24 hours whatever window is asked for, so a
    // caller reading them is never handed a different period under the same name.
    return res.json({
      totalUsers,
      activeSessions,
      newUsers24h: last24h.newUsers,
      loginSuccess24h: last24h.loginSuccess,
      loginFailed24h: last24h.loginFailed,
      successRate24h: last24h.successRate,
      otpUsage24h: last24h.otpUsage,
      passkeyUsage24h: last24h.passkeyUsage,
      databaseSize: dbSize,
      window: { from: window.start.toISOString(), to: window.end.toISOString() },
      ...(requested ?? last24h),
    });
  } catch {
    return res.status(500).json({ error: 'Failed to fetch dashboard metrics' });
  }
};
