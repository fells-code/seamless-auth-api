/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import cors, { CorsOptions } from 'cors';
import express, { NextFunction, Request, Response } from 'express';
import helmet from 'helmet';
import swaggerUi from 'swagger-ui-express';

import { mountAdminDashboard } from './lib/adminDashboard.js';
import { loadRoutes } from './lib/loadRoutes.js';
import { dynamicRateLimit } from './middleware/rateLimit.js';
import { logRoute } from './middleware/routeLogger.js';
import { dynamicSlowDown } from './middleware/slowDown.js';
import { applyTrustedClientIp } from './middleware/trustedClientIp.js';
import { generateOpenApiDocument } from './openapi/document.js';
import { AuthEventService } from './services/authEventService.js';
import getLogger from './utils/logger.js';

const logger = getLogger('app');
const app = express();

const rawOrigin = process.env.APP_ORIGINS!.split(',');

const corsOptions: CorsOptions = {
  origin: (origin, callback) => {
    if (!origin) {
      return callback(null, true);
    }

    if (rawOrigin.includes(origin)) {
      return callback(null, true);
    }

    logger.warn(`Unknown CORS origin: ${origin}`);
    void AuthEventService.requestSuspiciousContext(
      {
        ipAddress: origin,
        userAgent: 'unknown',
      },
      { reason: 'Unknown origin request' },
    );
    return callback(null, false);
  },
  credentials: true,
};

app.use(
  helmet({
    hidePoweredBy: true,
    frameguard: { action: 'deny' },
    xssFilter: true,
    noSniff: true,
  }),
);

const isDev = process.env.NODE_ENV !== 'production';

app.use(applyTrustedClientIp);

if (isDev) {
  app.get('/openapi.json', (_req, res) => {
    const document = generateOpenApiDocument();
    res.json(document);
  });

  app.use(
    '/docs',
    swaggerUi.serve,
    swaggerUi.setup(undefined, {
      swaggerOptions: {
        url: '/openapi.json',
      },
    }),
  );
}

if (process.env.NODE_ENV !== 'test') {
  app.use(dynamicSlowDown);
  app.use(dynamicRateLimit);
}

app.use(express.json());
app.use(cors(corsOptions));

app.use(logRoute);

export async function createApp() {
  await loadRoutes(app);

  // Additive static serving for the admin dashboard SPA at /console. Registered after the
  // API routes so the API always keeps priority, and before the 404 handler so unmatched
  // /console/* navigations fall back to the SPA instead of 404ing.
  mountAdminDashboard(app);

  app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
    if (err.message === 'Not allowed by CORS') {
      void AuthEventService.requestSuspicious(req, {
        reason: 'Request from an unexpected origin',
      });
      res.setHeader('Access-Control-Allow-Origin', rawOrigin[0]);
      return res.status(403).json({ message: 'CORS policy does not allow this origin.' });
    }
    return next();
  });

  app.use((err: unknown, req: Request, res: Response, next: NextFunction) => {
    if (err) {
      logger.error('Unhandled error', err);

      return res.status(500).json({
        error: 'Internal server error',
      });
    }

    return next();
  });

  app.use((req: Request, res: Response) => {
    logger.warn(
      `[${req.ip}] ${req.method} ${req.originalUrl} did not match any route. Tracking suspicious behavior`,
    );
    void AuthEventService.requestSuspicious(req, {
      reason: 'Request to an unknown route.',
      method: req.method,
      path: req.originalUrl,
    });
    return res.status(404).json({ error: 'Not Found' });
  });

  return app;
}

export default app;
