/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import {
  finishOAuthLogin,
  listOAuthProviders,
  startOAuthLogin,
} from '../controllers/oauth.js';
import { createRouter } from '../lib/createRouter.js';
import {
  FinishOAuthLoginRequestSchema,
  OAuthProviderParamSchema,
  StartOAuthLoginRequestSchema,
} from '../schemas/oauth.requests.js';

const oauthRouter = createRouter('/oauth');

oauthRouter.get(
  '/providers',
  {
    summary: 'List enabled OAuth providers',
    tags: ['OAuth'],
  },
  listOAuthProviders,
);

oauthRouter.post(
  '/:providerId/start',
  {
    summary: 'Start OAuth login',
    tags: ['OAuth'],
    schemas: {
      params: OAuthProviderParamSchema,
      body: StartOAuthLoginRequestSchema,
    },
  },
  startOAuthLogin,
);

oauthRouter.post(
  '/:providerId/callback',
  {
    summary: 'Finish OAuth login',
    tags: ['OAuth'],
    schemas: {
      params: OAuthProviderParamSchema,
      body: FinishOAuthLoginRequestSchema,
    },
  },
  finishOAuthLogin,
);

export default oauthRouter.router;
