import { Request, Response } from 'express';
import { col, fn, literal, Op } from 'sequelize';

import { AuthEvent } from '../models/authEvents.js';
import { MetricsQuerySchema } from '../schemas/internal.metrics.query.js';
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

  const { from, to, interval } = parsed.data;

  const where: any = {};

  if (from || to) {
    where.created_at = {};
    if (from) where.created_at[Op.gte] = new Date(from);
    if (to) where.created_at[Op.lte] = new Date(to);
  }

  const bucket =
    interval === 'day'
      ? literal(`DATE_TRUNC('day', created_at)`)
      : literal(`DATE_TRUNC('hour', created_at)`);

  try {
    const results = await AuthEvent.findAll({
      attributes: [
        [bucket, 'bucket'],
        [fn('COUNT', col('id')), 'count'],
      ],
      where,
      group: ['bucket'],
      order: [[literal('bucket'), 'ASC']],
    });

    return res.json({
      timeseries: results.map((r: any) => ({
        bucket: r.get('bucket'),
        count: Number(r.get('count')),
      })),
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
