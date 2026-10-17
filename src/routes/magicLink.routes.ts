/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { decoyPollMagicLink, decoyRequestMagicLink } from '../controllers/decoyResponders.js';
import {
  confirmMagicLink,
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
import {
  MagicLinkConfirmationRequiredSchema,
  MagicLinkPollResponseSchema,
} from '../schemas/magiclink.responses.js';

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
        200: MagicLinkPollResponseSchema,
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
    description:
      'Consumes the link when it is opened on the device that requested it, proven by the ' +
      "requesting attempt's ephemeral bearer token when the adapter forwards it, otherwise by " +
      'the IP address and user agent a trusted adapter forwards. Opened anywhere else, answers ' +
      '409 without consuming it; ' +
      'confirm with POST /magic-link/verify/{token}/confirm.',
    tags: ['MagicLinks'],

    schemas: {
      params: MagicLinkVerifyParamsSchema,

      response: {
        200: MessageSchema,
        403: ErrorSchema,
        400: ErrorSchema,
        409: MagicLinkConfirmationRequiredSchema,
        500: InternalErrorSchema,
      },
    },
  },
  verifyMagicLink,
);

magicLinkRouter.post(
  '/verify/:token/confirm',
  {
    adapter: {},
    summary: 'Confirm a magic link opened on another device',
    description:
      'Consumes the link after the person who opened it has approved signing in the device ' +
      'that requested it.',
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
  confirmMagicLink,
);

export default magicLinkRouter.router;
