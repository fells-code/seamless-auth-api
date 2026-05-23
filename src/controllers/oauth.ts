/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { Request, Response } from 'express';

import { getSystemConfig } from '../config/getSystemConfig.js';
import { AuthEventService } from '../services/authEventService.js';
import {
  buildOAuthAuthorizationUrl,
  createOAuthState,
  exchangeOAuthCode,
  fetchOAuthProfile,
  getEnabledOAuthProviders,
  getOAuthProvider,
  resolveOAuthRedirectUri,
  resolveOAuthUser,
  serializeOAuthProvider,
  verifyOAuthState,
} from '../services/oauthService.js';
import { issueSessionAndRespond } from '../services/sessionIssuance.js';

const AUTH_MODE: 'web' | 'server' = process.env.AUTH_MODE! as 'web' | 'server';

function allowedReturnTo(value: string | undefined, origins: string[]) {
  if (!value) return undefined;
  return origins.some((origin) => value.startsWith(origin)) ? value : undefined;
}

export async function listOAuthProviders(_req: Request, res: Response) {
  const providers = await getEnabledOAuthProviders();

  return res.json({
    providers: providers.map(serializeOAuthProvider),
  });
}

export async function startOAuthLogin(req: Request, res: Response) {
  const { providerId } = req.params;
  const provider = await getOAuthProvider(providerId);

  if (!provider) {
    return res.status(404).json({ error: 'OAuth provider not found' });
  }

  try {
    const config = await getSystemConfig();
    const redirectUri = await resolveOAuthRedirectUri(provider, req.body.redirectUri);
    const returnTo = allowedReturnTo(req.body.returnTo, config.origins);
    const state = createOAuthState({
      providerId: provider.id,
      redirectUri,
      ...(returnTo ? { returnTo } : {}),
    });

    await AuthEventService.log({
      type: 'oauth_login_started',
      req,
      metadata: { providerId: provider.id },
    });

    return res.json({
      provider: serializeOAuthProvider(provider),
      state,
      authorizationUrl: buildOAuthAuthorizationUrl({
        provider,
        redirectUri,
        state,
      }),
    });
  } catch (error) {
    await AuthEventService.log({
      type: 'oauth_login_failed',
      req,
      metadata: { providerId: provider.id, reason: 'start_failed' },
    });

    return res.status(400).json({
      error: error instanceof Error ? error.message : 'OAuth start failed',
    });
  }
}

export async function finishOAuthLogin(req: Request, res: Response) {
  const { providerId } = req.params;
  const { code, state } = req.body;
  const provider = await getOAuthProvider(providerId);

  if (!provider) {
    return res.status(404).json({ error: 'OAuth provider not found' });
  }

  const statePayload = verifyOAuthState(state, provider.id);

  if (!statePayload) {
    await AuthEventService.log({
      type: 'oauth_login_failed',
      req,
      metadata: { providerId: provider.id, reason: 'invalid_state' },
    });
    return res.status(400).json({ error: 'Invalid OAuth state' });
  }

  try {
    const accessToken = await exchangeOAuthCode({
      provider,
      code,
      redirectUri: statePayload.redirectUri,
    });
    const profile = await fetchOAuthProfile(provider, accessToken);
    const user = await resolveOAuthUser(provider, profile);

    if (!user) {
      await AuthEventService.log({
        type: 'oauth_login_failed',
        req,
        metadata: { providerId: provider.id, reason: 'signup_disabled' },
      });
      return res.status(403).json({ error: 'OAuth signup is disabled' });
    }

    await AuthEventService.log({
      userId: user.id,
      type: 'oauth_login_success',
      req,
      metadata: { providerId: provider.id },
    });

    return issueSessionAndRespond({
      user: {
        id: user.id,
        email: user.email,
        phone: user.phone,
        roles: user.roles ?? [],
      },
      req,
      res,
      authMode: AUTH_MODE,
      clearExistingCookies: true,
    });
  } catch (error) {
    await AuthEventService.log({
      type: 'oauth_login_failed',
      req,
      metadata: { providerId: provider.id, reason: 'callback_failed' },
    });

    return res.status(400).json({
      error: error instanceof Error ? error.message : 'OAuth login failed',
    });
  }
}
