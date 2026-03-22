import { getAuthEvents, getCredentialsCount, getLogs, getUsers } from '../controllers/internal.js';
import { getDashboardMetrics } from '../controllers/internalDashboard.js';
import {
  getAuthEventSummary,
  getAuthEventTimeseries,
  getLoginStats,
} from '../controllers/internalMetrics.js';
import { getSecurityAnomalies } from '../controllers/internalSecurity.js';
import { createRouter } from '../lib/createRouter.js';
import { verifyServiceToken } from '../middleware/authenticateServiceToken.js';
import { MetricsQuerySchema } from '../schemas/internal.metrics.query.js';
import { AuthEventQuerySchema } from '../schemas/internal.query.js';
import {
  AuthEventsResponseSchema,
  CredentialCountSchema,
  InternalErrorSchema,
  LogsResponseSchema,
  UsersListResponseSchema,
} from '../schemas/internal.responses.js';

const internalRouter = createRouter('/internal');

internalRouter.get(
  '/users',
  {
    summary: 'List users (internal)',
    tags: ['Internal'],
    middleware: [verifyServiceToken],

    schemas: {
      response: {
        200: UsersListResponseSchema,
        500: InternalErrorSchema,
      },
    },
  },
  getUsers,
);

internalRouter.get(
  '/auth-events',
  {
    middleware: [verifyServiceToken],
    tags: ['Internal'],
    schemas: {
      query: AuthEventQuerySchema,
      response: {
        200: AuthEventsResponseSchema,
      },
    },
  },
  getAuthEvents,
);

internalRouter.get(
  '/credential-count',
  {
    summary: 'Get credential count',
    tags: ['Internal'],
    middleware: [verifyServiceToken],

    schemas: {
      response: {
        200: CredentialCountSchema,
        500: InternalErrorSchema,
      },
    },
  },
  getCredentialsCount,
);

internalRouter.get(
  '/logs',
  {
    summary: 'Fetch logs (dev only)',
    tags: ['Internal'],
    middleware: [verifyServiceToken],

    schemas: {
      response: {
        200: LogsResponseSchema,
        500: InternalErrorSchema,
      },
    },
  },
  getLogs,
);

internalRouter.get(
  '/auth-events/summary',
  {
    middleware: [verifyServiceToken],
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
    middleware: [verifyServiceToken],
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
    middleware: [verifyServiceToken],
    tags: ['Internal'],
  },
  getLoginStats,
);

internalRouter.get(
  '/security/anomalies',
  {
    middleware: [verifyServiceToken],
    summary: 'Detect suspicious activity',
    tags: ['Internal'],
  },
  getSecurityAnomalies,
);

internalRouter.get(
  '/metrics/dashboard',
  {
    middleware: [verifyServiceToken],
    summary: 'Dashboard metrics',
    tags: ['Internal'],
  },
  getDashboardMetrics,
);

export default internalRouter.router;
