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
import { requireAdmin } from '../middleware/requireAdmin.js';
import { MessageSchema } from '../schemas/generic.responses.js';
import { MetricsQuerySchema } from '../schemas/internal.query.js';
import {
  AuthEventSummaryResponseSchema,
  AuthEventTimeseriesResponseSchema,
  DashboardMetricsResponseSchema,
  LoginStatsResponseSchema,
  SecurityAnomaliesResponseSchema,
} from '../schemas/internalMetrics.responses.js';

const internalRouter = createRouter('/internal');

internalRouter.get(
  '/auth-events/summary',
  {
    auth: 'access',
    middleware: [requireAdmin('read')],
    tags: ['Internal'],
    schemas: {
      query: MetricsQuerySchema,
      response: {
        200: AuthEventSummaryResponseSchema,
        400: MessageSchema,
        500: MessageSchema,
      },
    },
  },
  getAuthEventSummary,
);

internalRouter.get(
  '/auth-events/timeseries',
  {
    auth: 'access',
    middleware: [requireAdmin('read')],
    tags: ['Internal'],
    schemas: {
      query: MetricsQuerySchema,
      response: {
        200: AuthEventTimeseriesResponseSchema,
        400: MessageSchema,
        500: MessageSchema,
      },
    },
  },
  getAuthEventTimeseries,
);

internalRouter.get(
  '/auth-events/login-stats',
  {
    auth: 'access',
    middleware: [requireAdmin('read')],
    tags: ['Internal'],
    schemas: {
      response: {
        200: LoginStatsResponseSchema,
        500: MessageSchema,
      },
    },
  },
  getLoginStats,
);

internalRouter.get(
  '/security/anomalies',
  {
    auth: 'access',
    middleware: [requireAdmin('read')],
    summary: 'Detect suspicious activity',
    tags: ['Internal'],
    schemas: {
      response: {
        200: SecurityAnomaliesResponseSchema,
        500: MessageSchema,
      },
    },
  },
  getSecurityAnomalies,
);

internalRouter.get(
  '/metrics/dashboard',
  {
    auth: 'access',
    middleware: [requireAdmin('read')],
    summary: 'Dashboard metrics',
    tags: ['Internal'],
    schemas: {
      response: {
        200: DashboardMetricsResponseSchema,
        500: MessageSchema,
      },
    },
  },
  getDashboardMetrics,
);

internalRouter.get(
  '/auth-events/grouped',
  {
    auth: 'access',
    middleware: [requireAdmin('read')],
    summary: 'Auth Event metrics grouped',
    tags: ['Internal'],
    schemas: {
      response: {
        200: AuthEventSummaryResponseSchema,
        500: MessageSchema,
      },
    },
  },
  getGroupedEventSummary,
);

export default internalRouter.router;
