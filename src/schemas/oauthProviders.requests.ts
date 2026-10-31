/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { OAuthProviderConfigSchema } from '@seamless-auth/types';
import { z } from 'zod';

export {
  OAuthProviderCreateSchema,
  OAuthProviderIdParamSchema,
  OAuthProviderUpdateSchema,
} from '@seamless-auth/types';

/**
 * A provider added from its issuer. The endpoints come from the issuer's discovery
 * document, and any given here are kept over the discovered ones.
 */
export const OAuthProviderDiscoverSchema = OAuthProviderConfigSchema.extend({
  issuer: z.url({ protocol: /^https?$/ }),
  authorizationUrl: OAuthProviderConfigSchema.shape.authorizationUrl.optional(),
  tokenUrl: OAuthProviderConfigSchema.shape.tokenUrl.optional(),
  userInfoUrl: OAuthProviderConfigSchema.shape.userInfoUrl.optional(),
  scopes: OAuthProviderConfigSchema.shape.scopes.unwrap().default(['openid', 'email', 'profile']),
});
