/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import cookieParser from 'cookie-parser';
import cors, { CorsOptions } from 'cors';
import express, { Request, Response } from 'express';
import helmet from 'helmet';

import { login, logout, refreshSession } from './controllers/authentication';
import { jwksHandler } from './controllers/jwks';
import { attachAuthMiddleware } from './middleware/attachAuthMiddleware';
import { dynamicJWKSRateLimit } from './middleware/jwksRateLimit';
import { dynamicRateLimit } from './middleware/rateLimit';
import { dynamicSlowDown } from './middleware/slowDown';
import { verifyBearerAuth } from './middleware/verifyBearerAuth';
import { AuthEvent } from './models/authEvents';
import health from './routes/health';
import otp from './routes/otp';
import registration from './routes/registration';
import systemConfigRouter from './routes/systemConfig';
import user from './routes/user';
import webAuthn from './routes/webauthn';
import getLogger from './utils/logger';

const logger = getLogger('app');
const app = express();

const isValidUrl = (str: string) => {
  try {
    if (str === '*') return true;
    new URL(str);
    return true;
  } catch {
    throw new Error('Invalid host provied.');
  }
};

const rawOrigin = process.env.APP_ORIGIN?.trim();
const allowedOrigin = rawOrigin && isValidUrl(rawOrigin) ? rawOrigin : '';

const corsOptions: CorsOptions = {
  origin: (origin, callback) => {
    if (!origin) {
      return callback(null, true);
    }

    if (process.env.DEMO === 'true') {
      // Local development mode
      if (origin === 'http://localhost:5001' || origin === 'http://localhost:3000') {
        return callback(null, true);
      }
    }

    if (origin === allowedOrigin) {
      return callback(null, true);
    }

    logger.warn(`Unknown CORS origin: ${origin}`);
    AuthEvent.create({
      user_id: null,
      type: 'request_suspicious',
      ip_address: origin,
      user_agent: 'unknown',
      metadata: { reason: 'Unknown origin request' },
    });
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

app.use('/health', health);
app.use(dynamicSlowDown);
app.use(dynamicRateLimit);

app.use(express.json());

app.use('/.well-known/jwks.json', dynamicJWKSRateLimit, jwksHandler);

app.use(cors(corsOptions));
app.use(cookieParser());

const startServer = async () => {
  try {
    app.use('/login', login);
    app.use('/logout', attachAuthMiddleware('access'), logout);
    app.use('/registration', registration);
    app.use('/webAuthn', webAuthn);
    app.use('/users', user);
    app.use('/otp', otp);

    // API only routes
    app.use('/system-config', systemConfigRouter);
    app.use('/refresh', verifyBearerAuth, refreshSession);

    app.use((err: Error, req: Request, res: Response) => {
      if (err.message === 'Not allowed by CORS') {
        AuthEvent.create({
          user_id: 'null',
          type: 'request_suspicous',
          ip_address: req.ip,
          user_agent: req.headers['user-agent'],
          metadata: { reason: 'Request from an unexpected origin' },
        });
        res.setHeader('Access-Control-Allow-Origin', process.env.APP_ORIGIN!);
        return res.status(403).json({ message: 'CORS policy does not allow this origin.' });
      }
    });

    app.use((req: Request, res: Response) => {
      logger.warn(
        `[${req.ip}] didn't make it anywhere. Path: ${req.path}. Tracking of suspicous behavior`,
      );
      AuthEvent.create({
        user_id: 'null',
        type: 'request_suspicous',
        ip_address: req.ip,
        user_agent: req.headers['user-agent'],
        metadata: { reason: 'Request to an unknown route.' },
      });
      res.status(404).json({ error: 'Not Found' });
    });
  } catch (error: unknown) {
    if (error instanceof Error) {
      logger.error(`Failed to start server: ${error.message}`);
    } else {
      logger.error(`Failed to start server: ${String(error)}`);
    }

    process.exit(1);
  }
};

startServer();

export default app;
