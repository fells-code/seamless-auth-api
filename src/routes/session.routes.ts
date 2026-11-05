/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import {
  exchangeSession,
  listSessions,
  revokeAllSessions,
  revokeSession,
} from '../controllers/sessions.js';
import { createRouter } from '../lib/createRouter.js';
import { sessionExchangeLimiter } from '../middleware/rateLimit.js';
import { ErrorSchema, MessageSchema, ValidationErrorSchema } from '../schemas/generic.responses.js';
import { SessionIdParamsSchema } from '../schemas/session.params.js';
import {
  SessionExchangeErrorSchema,
  SessionExchangeRequestSchema,
  SessionExchangeResponseSchema,
  SessionListResponseSchema,
} from '../schemas/session.responses.js';

const sessionsRouter = createRouter('/sessions');

sessionsRouter.get(
  '',
  {
    auth: 'access',
    summary: 'List active sessions',
    tags: ['Sessions'],

    schemas: {
      response: {
        200: SessionListResponseSchema,
        401: ErrorSchema,
      },
    },
  },
  listSessions,
);

sessionsRouter.post(
  '/exchange',
  {
    adapter: false,
    middleware: [sessionExchangeLimiter],
    summary: 'Exchange a provider sign-in for a first-party session',
    description:
      'For first-party public native clients signed in through the OpenID Provider (ADR 0003). Takes the provider access token for `<oidc_issuer>/seamless` with the single `session:exchange` scope, once, and returns the same session `/refresh` returns, for a new session linked to the provider sign-in. Every subject token failure answers the same `400 invalid_request`. A second presentation adds `error_description: token_already_used` and revokes the session the first one created.',
    tags: ['Sessions'],

    schemas: {
      body: SessionExchangeRequestSchema,

      response: {
        200: SessionExchangeResponseSchema,
        // Also what a request that fails schema validation answers with.
        400: SessionExchangeErrorSchema.extend(
          ValidationErrorSchema.pick({
            message: true,
            details: true,
          }).shape,
        ),
      },
    },
  },
  exchangeSession,
);

sessionsRouter.delete(
  '/:id',
  {
    auth: 'access',
    summary: 'Revoke a session',
    tags: ['Sessions'],

    schemas: {
      params: SessionIdParamsSchema,

      response: {
        200: MessageSchema,
        401: ErrorSchema,
        404: ErrorSchema,
      },
    },
  },
  revokeSession,
);

sessionsRouter.delete(
  '',
  {
    auth: 'access',
    summary: 'Revoke all sessions',
    tags: ['Sessions'],

    schemas: {
      response: {
        200: MessageSchema,
        401: ErrorSchema,
      },
    },
  },
  revokeAllSessions,
);

export default sessionsRouter.router;
