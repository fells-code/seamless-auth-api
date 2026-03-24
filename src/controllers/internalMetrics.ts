import { Request, Response } from 'express';
import { col, fn, literal, Op } from 'sequelize';

import { AuthEvent } from '../models/authEvents.js';
import { MetricsQuerySchema } from '../schemas/internal.query.js';
import getLogger from '../utils/logger.js';

const logger = getLogger('internal-metrics');

export const getAuthEventSummary = async (req: Request, res: Response) => {
  const parsed = MetricsQuerySchema.safeParse(req.query);

  if (!parsed.success) {
    return res.status(400).json({ message: 'Invalid query params' });
  }

  const { from, to } = parsed.data;

  const where: any = {};

  if (from || to) {
    where.created_at = {};
    if (from) where.created_at[Op.gte] = new Date(from);
    if (to) where.created_at[Op.lte] = new Date(to);
  }

  try {
    const results = await AuthEvent.findAll({
      attributes: ['type', [fn('COUNT', col('type')), 'count']],
      where,
      group: ['type'],
    });

    return res.json({
      summary: results.map((r: any) => ({
        type: r.type,
        count: Number(r.get('count')),
      })),
    });
  } catch (err) {
    logger.error(`Failed to fetch auth summary: ${err}`);
    return res.status(500).json({ message: 'Failed to fetch summary' });
  }
};

export const getAuthEventTimeseries = async (req: Request, res: Response) => {
  const parsed = MetricsQuerySchema.safeParse(req.query);

  if (!parsed.success) {
    return res.status(400).json({ message: 'Invalid query params' });
  }

  const { from, to, interval, userId } = parsed.data;

  const where: any = {
    type: {
      [Op.in]: ['login_success', 'login_failed'],
    },
  };

  if (userId) {
    where.user_id = req.query.userId;
  }

  // Default to last 24h if not provided
  const now = new Date();
  const defaultFrom = new Date(now.getTime() - 1000 * 60 * 60 * 24);

  if (from || to) {
    where.created_at = {};
    if (from) where.created_at[Op.gte] = new Date(from);
    if (to) where.created_at[Op.lte] = new Date(to);
  } else {
    where.created_at = {
      [Op.gte]: defaultFrom,
    };
  }

  const bucket =
    interval === 'day'
      ? literal(`DATE_TRUNC('day', created_at)`)
      : literal(`DATE_TRUNC('hour', created_at)`);

  try {
    const results = await AuthEvent.findAll({
      attributes: [[bucket, 'bucket'], 'type', [fn('COUNT', col('id')), 'count']],
      where,
      group: ['bucket', 'type'],
      order: [[literal('bucket'), 'ASC']],
    });

    const map: Record<string, any> = {};

    for (const r of results as any[]) {
      const bucket = new Date(r.get('bucket')).toISOString();
      const type = r.get('type');
      const count = Number(r.get('count'));

      if (!map[bucket]) {
        map[bucket] = {
          bucket,
          success: 0,
          failed: 0,
        };
      }

      if (type === 'login_success') {
        map[bucket].success = count;
      } else if (type === 'login_failed') {
        map[bucket].failed = count;
      }
    }

    const filled: any[] = [];

    if (interval === 'day') {
      for (let i = 29; i >= 0; i--) {
        const d = new Date(now);
        d.setUTCDate(d.getUTCDate() - i);
        d.setUTCHours(0, 0, 0, 0);

        const key = d.toISOString();

        filled.push({
          bucket: key,
          success: map[key]?.success ?? 0,
          failed: map[key]?.failed ?? 0,
        });
      }
    } else {
      for (let i = 23; i >= 0; i--) {
        const d = new Date(now);
        d.setUTCHours(d.getUTCHours() - i, 0, 0, 0);

        const key = d.toISOString();

        filled.push({
          bucket: key,
          success: map[key]?.success ?? 0,
          failed: map[key]?.failed ?? 0,
        });
      }
    }

    return res.json({
      timeseries: filled,
    });
  } catch (err) {
    logger.error(`Failed to fetch timeseries: ${err}`);
    return res.status(500).json({ message: 'Failed to fetch timeseries' });
  }
};

export const getLoginStats = async (req: Request, res: Response) => {
  try {
    const success = await AuthEvent.count({
      where: { type: 'login_success' },
    });

    const failed = await AuthEvent.count({
      where: { type: 'login_failed' },
    });

    return res.json({
      success,
      failed,
      successRate: success + failed > 0 ? success / (success + failed) : 0,
    });
  } catch (err) {
    return res.status(500).json({ message: 'Failed to compute login stats' });
  }
};

export const getGroupedEventSummary = async (_req: Request, res: Response) => {
  try {
    const events = await AuthEvent.findAll();

    const grouped = {
      login: 0,
      otp: 0,
      webauthn: 0,
      magicLink: 0,
      system: 0,
      suspicious: 0,
      other: 0,
    };

    for (const e of events) {
      const type = e.type;

      if (type.includes('login')) grouped.login++;
      else if (type.includes('otp')) grouped.otp++;
      else if (type.includes('webauthn')) grouped.webauthn++;
      else if (type.includes('magic_link')) grouped.magicLink++;
      else if (type.includes('system_config')) grouped.system++;
      else if (type.includes('suspicious')) grouped.suspicious++;
      else grouped.other++;
    }

    return res.json({
      summary: Object.entries(grouped).map(([type, count]) => ({
        type,
        count,
      })),
    });
  } catch {
    return res.status(500).json({ message: 'Failed to group events' });
  }
};
