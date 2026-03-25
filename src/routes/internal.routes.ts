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
import { verifyServiceToken } from '../middleware/authenticateServiceToken.js';
import { requireAdmin } from '../middleware/requireAdmin.js';
import { MetricsQuerySchema } from '../schemas/internal.query.js';

const internalRouter = createRouter('/internal');

internalRouter.get(
  '/auth-events/summary',
  {
    middleware: [verifyServiceToken, attachAuthMiddleware(), requireAdmin()],
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
    middleware: [verifyServiceToken, attachAuthMiddleware(), requireAdmin()],
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
    middleware: [verifyServiceToken, attachAuthMiddleware(), requireAdmin()],
    tags: ['Internal'],
  },
  getLoginStats,
);

internalRouter.get(
  '/security/anomalies',
  {
    middleware: [verifyServiceToken, attachAuthMiddleware(), requireAdmin()],
    summary: 'Detect suspicious activity',
    tags: ['Internal'],
  },
  getSecurityAnomalies,
);

internalRouter.get(
  '/metrics/dashboard',
  {
    middleware: [verifyServiceToken, attachAuthMiddleware(), requireAdmin()],
    summary: 'Dashboard metrics',
    tags: ['Internal'],
  },
  getDashboardMetrics,
);

internalRouter.get(
  '/auth-events/grouped',
  {
    middleware: [verifyServiceToken, attachAuthMiddleware(), requireAdmin()],
    summary: 'Auth Event metrics grouped',
    tags: ['Internal'],
  },
  getGroupedEventSummary,
);

export default internalRouter.router;
