/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { getDashboardMetrics } from '../controllers/internalDashboard.js';
import {
  getAuthEventSummary,
  getAuthEventTimeseries,
  getGroupedEventSummary,
  getLoginStats,
} from '../controllers/internalMetrics.js';
import { getSecurityAnomalies } from '../controllers/internalSecurity.js';
import { createRouter } from '../lib/createRouter.js';
import { attachAuthMiddleware } from '../middleware/attachAuthMiddleware.js';
import { requireAdmin } from '../middleware/requireAdmin.js';
import { MetricsQuerySchema } from '../schemas/internal.query.js';

const internalRouter = createRouter('/internal');

internalRouter.get(
  '/auth-events/summary',
  {
    middleware: [attachAuthMiddleware(), requireAdmin()],
    tags: ['Internal'],
    schemas: {
      query: MetricsQuerySchema,
    },
  },
  getAuthEventSummary,
);

internalRouter.get(
  '/auth-events/timeseries',
  {
    middleware: [attachAuthMiddleware(), requireAdmin()],
    tags: ['Internal'],
    schemas: {
      query: MetricsQuerySchema,
    },
  },
  getAuthEventTimeseries,
);

internalRouter.get(
  '/auth-events/login-stats',
  {
    middleware: [attachAuthMiddleware(), requireAdmin()],
    tags: ['Internal'],
  },
  getLoginStats,
);

internalRouter.get(
  '/security/anomalies',
  {
    middleware: [attachAuthMiddleware(), requireAdmin()],
    summary: 'Detect suspicious activity',
    tags: ['Internal'],
  },
  getSecurityAnomalies,
);

internalRouter.get(
  '/metrics/dashboard',
  {
    middleware: [attachAuthMiddleware(), requireAdmin()],
    summary: 'Dashboard metrics',
    tags: ['Internal'],
  },
  getDashboardMetrics,
);

internalRouter.get(
  '/auth-events/grouped',
  {
    middleware: [attachAuthMiddleware(), requireAdmin()],
    summary: 'Auth Event metrics grouped',
    tags: ['Internal'],
  },
  getGroupedEventSummary,
);

export default internalRouter.router;
