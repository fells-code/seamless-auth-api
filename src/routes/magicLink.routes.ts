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
  MagicLinkConfirmBodySchema,
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
        503: ErrorSchema,
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
      'Describes the link without consuming it, always answering 409 confirmation_required. ' +
      '`sameDevice` is true when it was opened by the attempt that requested it, proven by ' +
      "that attempt's ephemeral bearer token when the adapter forwards it, otherwise by the " +
      'IP address and user agent a trusted adapter forwards. Consume it with ' +
      'POST /magic-link/verify/{token}/confirm and the code from the link fragment.',
    tags: ['MagicLinks'],

    schemas: {
      params: MagicLinkVerifyParamsSchema,

      response: {
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
    summary: 'Confirm a magic link',
    description:
      'Consumes the link, signing in the device that requested it. Takes the `code` the link ' +
      'carries in its fragment (`#code=`), which never appears in a query string or a ' +
      'Referer. A wrong code spends the link.',
    tags: ['MagicLinks'],

    schemas: {
      params: MagicLinkVerifyParamsSchema,
      body: MagicLinkConfirmBodySchema,

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
