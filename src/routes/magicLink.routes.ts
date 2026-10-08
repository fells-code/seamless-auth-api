/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { decoyPollMagicLink, decoyRequestMagicLink } from '../controllers/decoyResponders.js';
import {
  pollMagicLinkConfirmation,
  requestMagicLink,
  verifyMagicLink,
} from '../controllers/magicLinks.js';
import { createRouter } from '../lib/createRouter.js';
import { magicLinkEmailLimiter, magicLinkIpLimiter } from '../middleware/rateLimit.js';
import { ErrorSchema, InternalErrorSchema, MessageSchema } from '../schemas/generic.responses.js';
import {
  MagicLinkRequestQuerySchema,
  MagicLinkVerifyParamsSchema,
} from '../schemas/magiclink.requests.js';
import { MagicLinkPollSuccessSchema } from '../schemas/magiclink.responses.js';

const magicLinkRouter = createRouter('/magic-link');

magicLinkRouter.post(
  '',
  {
    adapter: { credential: 'preAuth', delivery: true },
    auth: 'ephemeral',
    summary: 'Request a magic login link',
    decoy: decoyRequestMagicLink,
    tags: ['MagicLinks'],
    middleware: [magicLinkIpLimiter, magicLinkEmailLimiter],

    schemas: {
      query: MagicLinkRequestQuerySchema,
      response: {
        200: MessageSchema,
        400: ErrorSchema,
        403: ErrorSchema,
        500: InternalErrorSchema,
      },
    },
  },
  requestMagicLink,
);

magicLinkRouter.get(
  '',
  {
    adapter: false,
    deprecated: true,
    description:
      'Use POST. A GET that sends a message can be triggered cross-site without a CORS preflight.',
    auth: 'ephemeral',
    summary: 'Request a magic login link',
    decoy: decoyRequestMagicLink,
    tags: ['MagicLinks'],
    middleware: [magicLinkIpLimiter, magicLinkEmailLimiter],

    schemas: {
      query: MagicLinkRequestQuerySchema,
      response: {
        200: MessageSchema,
        400: ErrorSchema,
        403: ErrorSchema,
        500: InternalErrorSchema,
      },
    },
  },
  requestMagicLink,
);

magicLinkRouter.get(
  '/check',
  {
    adapter: { credential: 'preAuth', issues: 'session' },
    auth: 'ephemeral',
    summary: 'Poll for magic link confirmation',
    decoy: decoyPollMagicLink,
    tags: ['MagicLinks'],

    schemas: {
      response: {
        200: MagicLinkPollSuccessSchema,
        204: MessageSchema,
        403: ErrorSchema,
        404: ErrorSchema,
        500: InternalErrorSchema,
      },
    },
  },
  pollMagicLinkConfirmation,
);

magicLinkRouter.get(
  '/verify/:token',
  {
    adapter: {},
    summary: 'Verify magic link token',
    tags: ['MagicLinks'],

    schemas: {
      params: MagicLinkVerifyParamsSchema,

      response: {
        200: MessageSchema,
        403: ErrorSchema,
        400: ErrorSchema,
        500: InternalErrorSchema,
      },
    },
  },
  verifyMagicLink,
);

export default magicLinkRouter.router;
