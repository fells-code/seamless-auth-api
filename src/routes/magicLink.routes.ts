/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import {
  pollMagicLinkConfirmation,
  requestMagicLink,
  verifyMagicLink,
} from '../controllers/magicLinks.js';
import { createRouter } from '../lib/createRouter.js';
import { attachAuthMiddleware } from '../middleware/attachAuthMiddleware.js';
import { magicLinkEmailLimiter, magicLinkIpLimiter } from '../middleware/rateLimit.js';
import { MagicLinkVerifyParamsSchema } from '../schemas/magiclink.requests.js';
import {
  MagicLinkErrorSchema,
  MagicLinkPollPendingSchema,
  MagicLinkPollSuccessSchema,
  MagicLinkRequestResponseSchema,
  MagicLinkVerifyResponseSchema,
} from '../schemas/magiclink.responses.js';

const magicLinkRouter = createRouter('/magic-link');

magicLinkRouter.get(
  '',
  {
    summary: 'Request a magic login link',
    tags: ['MagicLinks'],
    middleware: [attachAuthMiddleware('ephemeral'), magicLinkIpLimiter, magicLinkEmailLimiter],

    schemas: {
      response: {
        200: MagicLinkRequestResponseSchema,
      },
    },
  },
  requestMagicLink,
);

magicLinkRouter.get(
  '/check',
  {
    summary: 'Poll for magic link confirmation',
    tags: ['MagicLinks'],
    middleware: [attachAuthMiddleware('ephemeral')],

    schemas: {
      response: {
        200: MagicLinkPollSuccessSchema,
        204: MagicLinkPollPendingSchema,
        500: MagicLinkErrorSchema,
      },
    },
  },
  pollMagicLinkConfirmation,
);

magicLinkRouter.get(
  '/verify/:token',
  {
    summary: 'Verify magic link token',
    tags: ['MagicLinks'],

    schemas: {
      params: MagicLinkVerifyParamsSchema,

      response: {
        200: MagicLinkVerifyResponseSchema,
        400: MagicLinkErrorSchema,
        500: MagicLinkErrorSchema,
      },
    },
  },
  verifyMagicLink,
);

export default magicLinkRouter.router;
