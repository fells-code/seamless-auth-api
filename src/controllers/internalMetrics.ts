/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { Request, Response } from 'express';
import { col, fn, literal, Op, WhereOptions } from 'sequelize';

import {
  AuthEventCategory,
  AuthEventOutcome,
  authEventOutcome,
  categorizeAuthEvent,
} from '../lib/authEventCategories.js';
import { AuthEvent, AuthEventAttributes } from '../models/authEvents.js';
import { MetricsInterval, MetricsQuerySchema } from '../schemas/internal.query.js';
import getLogger from '../utils/logger.js';

const logger = getLogger('internal-metrics');

const HOUR_MS = 1000 * 60 * 60;
const DAY_MS = HOUR_MS * 24;

const DEFAULT_BUCKET_COUNT: Record<MetricsInterval, number> = { hour: 24, day: 30 };

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
  total: number;
  categories: Partial<Record<AuthEventCategory, number>>;
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

type MetricsQuery = ReturnType<typeof MetricsQuerySchema.parse>;

function truncateToInterval(date: Date, interval: MetricsInterval): Date {
  const truncated = new Date(date);

  if (interval === 'day') {
    truncated.setUTCHours(0, 0, 0, 0);
  } else {
    truncated.setUTCMinutes(0, 0, 0);
  }

  return truncated;
}

// The buckets returned have to match the rows queried, otherwise a requested window is
// validated and then quietly replaced by a now-relative one in the output.
function resolveBucketWindow(
  from: Date | undefined,
  to: Date | undefined,
  interval: MetricsInterval,
) {
  const step = interval === 'day' ? DAY_MS : HOUR_MS;
  const last = truncateToInterval(to ?? new Date(), interval);
  const first = from
    ? truncateToInterval(from, interval)
    : new Date(last.getTime() - step * (DEFAULT_BUCKET_COUNT[interval] - 1));

  return { first, last, step };
}

function scopeWhere(
  query: MetricsQuery,
  from: Date | undefined,
  to: Date | undefined,
): WhereOptions<AuthEventAttributes> {
  return {
    ...(query.userId ? { user_id: query.userId } : {}),
    ...(from || to
      ? {
          created_at: {
            ...(from ? { [Op.gte]: from } : {}),
            ...(to ? { [Op.lte]: to } : {}),
          },
        }
      : {}),
  };
}

function parseMetricsQuery(req: Request) {
  const parsed = MetricsQuerySchema.safeParse(req.query);

  if (!parsed.success) return null;

  return {
    query: parsed.data,
    from: parsed.data.from ? new Date(parsed.data.from) : undefined,
    to: parsed.data.to ? new Date(parsed.data.to) : undefined,
  };
}

async function countByType(where: WhereOptions<AuthEventAttributes>) {
  const results = (await AuthEvent.findAll({
    attributes: ['type', [fn('COUNT', col('type')), 'count']],
    where,
    group: ['type'],
  })) as SummaryResultInstance[];

  return results.map((row) => ({ type: row.type, count: Number(row.get('count')) }));
}

export const getAuthEventSummary = async (req: Request, res: Response) => {
  const parsed = parseMetricsQuery(req);

  if (!parsed) {
    return res.status(400).json({ message: 'Invalid query params' });
  }

  const { query, from, to } = parsed;

  try {
    return res.json({ summary: await countByType(scopeWhere(query, from, to)) });
  } catch (err) {
    logger.error(`Failed to fetch auth summary: ${err}`);
    return res.status(500).json({ message: 'Failed to fetch summary' });
  }
};

export const getAuthEventTimeseries = async (req: Request, res: Response) => {
  const parsed = parseMetricsQuery(req);

  if (!parsed) {
    return res.status(400).json({ message: 'Invalid query params' });
  }

  const { query, from, to } = parsed;
  const { first, last, step } = resolveBucketWindow(from, to, query.interval);

  const where: WhereOptions<AuthEventAttributes> = {
    ...(query.userId ? { user_id: query.userId } : {}),
    created_at: {
      [Op.gte]: first,
      ...(to ? { [Op.lte]: to } : { [Op.lt]: new Date(last.getTime() + step) }),
    },
  };

  const bucket =
    query.interval === 'day'
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
      const key = new Date(r.get('bucket')).toISOString();
      const type = r.get('type');
      const count = Number(r.get('count'));

      map[key] ??= { bucket: key, success: 0, failed: 0, total: 0, categories: {} };

      const stats = map[key];
      const category = categorizeAuthEvent(type);

      stats.total += count;
      stats.categories[category] = (stats.categories[category] ?? 0) + count;

      if (type === 'login_success') {
        stats.success = count;
      } else if (type === 'login_failed') {
        stats.failed = count;
      }
    }

    const timeseries: BucketStats[] = [];

    for (let time = first.getTime(); time <= last.getTime(); time += step) {
      const key = new Date(time).toISOString();

      timeseries.push(map[key] ?? { bucket: key, success: 0, failed: 0, total: 0, categories: {} });
    }

    return res.json({ timeseries });
  } catch (err) {
    logger.error(`Failed to fetch timeseries: ${err}`);
    return res.status(500).json({ message: 'Failed to fetch timeseries' });
  }
};

export const getLoginStats = async (req: Request, res: Response) => {
  const parsed = parseMetricsQuery(req);

  if (!parsed) {
    return res.status(400).json({ message: 'Invalid query params' });
  }

  const { query, from, to } = parsed;
  const scope = scopeWhere(query, from, to);

  try {
    const success = await AuthEvent.count({ where: { ...scope, type: 'login_success' } });
    const failed = await AuthEvent.count({ where: { ...scope, type: 'login_failed' } });

    return res.json({
      success,
      failed,
      successRate: success + failed > 0 ? success / (success + failed) : 0,
    });
  } catch (err) {
    logger.error(`Failed to compute login stats: ${err}`);
    return res.status(500).json({ message: 'Failed to compute login stats' });
  }
};

export const getGroupedEventSummary = async (req: Request, res: Response) => {
  const parsed = parseMetricsQuery(req);

  if (!parsed) {
    return res.status(400).json({ message: 'Invalid query params' });
  }

  const { query, from, to } = parsed;

  try {
    const byType = await countByType(scopeWhere(query, from, to));

    const categories = new Map<AuthEventCategory, number>();
    const outcomes = new Map<AuthEventOutcome, number>();

    for (const { type, count } of byType) {
      const category = categorizeAuthEvent(type);
      const outcome = authEventOutcome(type);

      categories.set(category, (categories.get(category) ?? 0) + count);
      outcomes.set(outcome, (outcomes.get(outcome) ?? 0) + count);
    }

    return res.json({
      summary: [...categories].map(([type, count]) => ({ type, count })),
      outcomes: [...outcomes].map(([type, count]) => ({ type, count })),
    });
  } catch (err) {
    logger.error(`Failed to group auth events: ${err}`);
    return res.status(500).json({ message: 'Failed to group events' });
  }
};
