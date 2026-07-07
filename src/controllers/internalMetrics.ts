/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { Request, Response } from 'express';
import { col, fn, literal, Op, WhereOptions } from 'sequelize';

import { AuthEvent, AuthEventAttributes } from '../models/authEvents.js';
import { MetricsQuerySchema } from '../schemas/internal.query.js';
import getLogger from '../utils/logger.js';

const logger = getLogger('internal-metrics');

type TimeseriesRow = {
  bucket: Date | string;
  type: string;
  count: string | number;
};

type ResultInstance = {
  get<K extends keyof TimeseriesRow>(key: K): TimeseriesRow[K];
};

type BucketStats = {
  bucket: string;
  success: number;
  failed: number;
};

type SummaryRow = {
  type: string;
  count: string | number;
};

type SummaryResultInstance = {
  get<K extends keyof SummaryRow>(key: K): SummaryRow[K];
} & {
  type: string;
};

export const getAuthEventSummary = async (req: Request, res: Response) => {
  const parsed = MetricsQuerySchema.safeParse(req.query);

  if (!parsed.success) {
    return res.status(400).json({ message: 'Invalid query params' });
  }

  const { from, to } = parsed.data;

  const where: WhereOptions<AuthEventAttributes> =
    from || to
      ? {
          created_at: {
            ...(from ? { [Op.gte]: new Date(from) } : {}),
            ...(to ? { [Op.lte]: new Date(to) } : {}),
          },
        }
      : {};

  try {
    const results = (await AuthEvent.findAll({
      attributes: ['type', [fn('COUNT', col('type')), 'count']],
      where,
      group: ['type'],
    })) as SummaryResultInstance[];

    return res.json({
      summary: results.map((r: SummaryResultInstance) => ({
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

  // Default to last 24h if not provided
  const now = new Date();
  const defaultFrom = new Date(now.getTime() - 1000 * 60 * 60 * 24);

  const createdAtFilter =
    from || to
      ? {
          ...(from ? { [Op.gte]: new Date(from) } : {}),
          ...(to ? { [Op.lte]: new Date(to) } : {}),
        }
      : {
          [Op.gte]: defaultFrom,
        };

  const where: WhereOptions<AuthEventAttributes> = {
    type: {
      [Op.in]: ['login_success', 'login_failed'],
    },

    ...(userId ? { user_id: userId } : {}),

    created_at: createdAtFilter,
  };

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

    const map: Record<string, BucketStats> = {};

    for (const r of results as ResultInstance[]) {
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

    const filled: BucketStats[] = [];

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
    logger.error(`Failed to get Auth Events timeseries data. Reason: ${err}`);
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
