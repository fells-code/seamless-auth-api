/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { APPLICATION_NOTICE_SCOPE } from '@seamless-auth/types';

import { sendApplicationNoticeHandler } from '../controllers/applicationNotices.js';
import { createRouter } from '../lib/createRouter.js';
import {
  applicationNoticeClientLimiter,
  applicationNoticeUserLimiter,
} from '../middleware/applicationNoticeRateLimit.js';
import { requireApplicationToken } from '../middleware/requireApplicationToken.js';
import { SendApplicationNoticeRequestSchema } from '../schemas/applicationNotices.requests.js';
import {
  ApplicationNoticeErrorResponseSchema,
  SendApplicationNoticeResponseSchema,
} from '../schemas/applicationNotices.responses.js';
import { ValidationErrorSchema } from '../schemas/generic.responses.js';

const applicationsRouter = createRouter('/applications');

applicationsRouter.post(
  '/account-notices',
  {
    summary: "Send a user an account notice on a registered application's behalf",
    description:
      'For an application backend, with a client credentials token for the built-in `<oidc_issuer>/seamless` resource and scope `notices:send`, on a client an admin has enabled notices for. Sends to every verified channel of a user who holds a grant with the application, or to the channels named, inside a fixed template naming the application and the instance. The response lists channels, never addresses. A caller that owns delivery gets `deliveries` back instead, as on the account recovery routes.',
    tags: ['Applications'],
    adapter: false,
    middleware: [
      requireApplicationToken(APPLICATION_NOTICE_SCOPE),
      applicationNoticeClientLimiter,
      applicationNoticeUserLimiter,
    ],
    schemas: {
      body: SendApplicationNoticeRequestSchema,
      response: {
        200: SendApplicationNoticeResponseSchema,
        400: ValidationErrorSchema,
        401: ApplicationNoticeErrorResponseSchema,
        403: ApplicationNoticeErrorResponseSchema,
        404: ApplicationNoticeErrorResponseSchema,
        422: ApplicationNoticeErrorResponseSchema,
        429: ApplicationNoticeErrorResponseSchema,
      },
    },
  },
  sendApplicationNoticeHandler,
);

export default applicationsRouter.router;
