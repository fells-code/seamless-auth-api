/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { finishOAuthLogin, listOAuthProviders, startOAuthLogin } from '../controllers/oauth.js';
import { createRouter } from '../lib/createRouter.js';
import { oauthIpLimiter, oauthProviderLimiter } from '../middleware/rateLimit.js';
import { InternalErrorSchema } from '../schemas/generic.responses.js';
import {
  FinishOAuthLoginRequestSchema,
  OAuthProviderParamSchema,
  StartOAuthLoginRequestSchema,
} from '../schemas/oauth.requests.js';
import {
  OAuthLoginSuccessResponseSchema,
  OAuthProvidersResponseSchema,
  StartOAuthLoginResponseSchema,
} from '../schemas/oauth.responses.js';

const oauthRouter = createRouter('/oauth');

oauthRouter.get(
  '/providers',
  {
    summary: 'List enabled OAuth providers',
    tags: ['OAuth'],
    schemas: {
      response: {
        200: OAuthProvidersResponseSchema,
      },
    },
  },
  listOAuthProviders,
);

oauthRouter.post(
  '/:providerId/start',
  {
    summary: 'Start OAuth login',
    tags: ['OAuth'],
    middleware: [oauthIpLimiter, oauthProviderLimiter],
    schemas: {
      params: OAuthProviderParamSchema,
      body: StartOAuthLoginRequestSchema,
      response: {
        200: StartOAuthLoginResponseSchema,
        400: InternalErrorSchema,
        404: InternalErrorSchema,
      },
    },
  },
  startOAuthLogin,
);

oauthRouter.post(
  '/:providerId/callback',
  {
    summary: 'Finish OAuth login',
    tags: ['OAuth'],
    middleware: [oauthIpLimiter, oauthProviderLimiter],
    schemas: {
      params: OAuthProviderParamSchema,
      body: FinishOAuthLoginRequestSchema,
      response: {
        200: OAuthLoginSuccessResponseSchema,
        400: InternalErrorSchema,
        403: InternalErrorSchema,
        404: InternalErrorSchema,
      },
    },
  },
  finishOAuthLogin,
);

export default oauthRouter.router;
