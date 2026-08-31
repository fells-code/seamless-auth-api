/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import cors, { CorsOptionsDelegate } from 'cors';
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

// Express ignores X-Forwarded-For unless it is told how far to trust it, so behind a load
// balancer every request looks like it came from the balancer and the rate limiters bucket
// all clients together. Opt in per deployment: direct-to-internet installs must leave this
// unset, otherwise a client could forge the header and choose its own rate-limit bucket.
const trustProxy = process.env.TRUST_PROXY;
if (trustProxy) {
  const hops = Number(trustProxy);
  app.set('trust proxy', Number.isNaN(hops) ? trustProxy : hops);
}

// Express 5 changed the default query parser from "extended" to "simple". Pinned rather
// than inherited so an upgrade never silently changes how a caller's query string parses:
// this API is the contract source for the SDKs and the console, and none of them opted
// into a narrower parser.
app.set('query parser', 'extended');

const rawOrigin = process.env.APP_ORIGINS!.split(',');

export const CORS_REJECTION = 'Not allowed by CORS';

/**
 * Whether a request came from the host this server is itself being served on.
 *
 * A browser sends `Origin` on every state-changing request, same-origin ones
 * included, so the allowlist would otherwise refuse the admin console at
 * `/console`, which is served from this API's own origin and documented as
 * needing no CORS configuration.
 *
 * Host only, not scheme: behind a TLS-terminating proxy `req.protocol` reads
 * `http` unless `TRUST_PROXY` is set, and the console must not depend on that
 * being configured. Nothing is given away by the looser comparison, since anyone
 * able to serve content on this host has already won, and a caller that can forge
 * `Host` can equally send no `Origin` at all, which was always allowed.
 */
function isSameOrigin(req: Request, origin: string) {
  const host = req.get('host');

  if (!host) {
    return false;
  }

  try {
    return new URL(origin).host === host;
  } catch {
    return false;
  }
}

// A delegate rather than a plain `origin` function because that form is handed
// no request, and same-origin has to be told apart from cross-origin.
const corsOptionsDelegate: CorsOptionsDelegate<Request> = (req, callback) => {
  const origin = req.headers.origin;

  if (!origin || rawOrigin.includes(origin) || isSameOrigin(req, origin)) {
    return callback(null, { origin: true, credentials: true });
  }

  logger.warn(`Unknown CORS origin: ${origin}`);

  // Refused with an error rather than by omitting the response header. Omitting
  // it leaves the browser to discard a response the route has already produced,
  // which means a disallowed origin still executes the request.
  return callback(new Error(CORS_REJECTION));
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
app.use(cors<Request>(corsOptionsDelegate));

app.use(logRoute);

export async function createApp() {
  await loadRoutes(app);

  // Additive static serving for the admin dashboard SPA at /console. Registered after the
  // API routes so the API always keeps priority, and before the 404 handler so unmatched
  // /console/* navigations fall back to the SPA instead of 404ing.
  mountAdminDashboard(app);

  app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
    if (err.message === CORS_REJECTION) {
      // Recorded here rather than in the delegate so the event carries the real
      // client address and user agent, with the origin in a field that says origin.
      void AuthEventService.requestSuspicious(req, {
        reason: 'Request from an unexpected origin',
        origin: req.headers.origin ?? null,
      });
      // No Access-Control-Allow-Origin: naming an allowed origin to a caller that
      // is not one tells it part of the allowlist and helps the browser not at all.
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
