/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { Request, Response } from 'express';

import { getSystemConfig } from '../config/getSystemConfig.js';
import { Credential } from '../models/credentials.js';
import { AuthEventService } from '../services/authEventService.js';
import {
  buildOAuthAuthorizationUrl,
  consumeOAuthState,
  createOAuthPkceCodeChallenge,
  createOAuthPkceCodeVerifier,
  createOAuthState,
  exchangeOAuthTokens,
  fetchOAuthProfile,
  getEnabledOAuthProviders,
  getOAuthProvider,
  isOidcProvider,
  OAuthProfileError,
  oauthProfileFromIdToken,
  OAuthProviderRetiredError,
  resolveOAuthRedirectUri,
  resolveOAuthUser,
  serializeOAuthProvider,
  verifyOAuthIdToken,
} from '../services/oauthService.js';
import { issueSessionAndRespond } from '../services/sessionIssuance.js';
import { RouteRequest } from '../types/types.js';
import getLogger from '../utils/logger.js';

const logger = getLogger('oauth');

function allowedReturnTo(value: string | undefined, origins: string[]) {
  if (!value) return undefined;

  try {
    const url = new URL(value);
    return origins.some((origin) => url.origin === new URL(origin).origin) ? value : undefined;
  } catch {
    return undefined;
  }
}

export async function listOAuthProviders(_req: Request, res: Response) {
  const providers = await getEnabledOAuthProviders();

  return res.json({
    providers: providers.map(serializeOAuthProvider),
  });
}

export async function startOAuthLogin(req: RouteRequest, res: Response) {
  const { providerId } = req.params;
  const provider = await getOAuthProvider(providerId);

  if (!provider) {
    return res.status(404).json({ error: 'OAuth provider not found' });
  }

  try {
    const config = await getSystemConfig();
    const redirectUri = await resolveOAuthRedirectUri(provider, req.body.redirectUri);
    const returnTo = allowedReturnTo(req.body.returnTo, config.origins);
    const { state, payload: statePayload } = createOAuthState({
      providerId: provider.id,
      redirectUri,
      ...(returnTo ? { returnTo } : {}),
    });
    const codeChallenge = createOAuthPkceCodeChallenge(provider, statePayload);

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
        ...(statePayload.nonce ? { nonce: statePayload.nonce } : {}),
        ...(codeChallenge ? { codeChallenge } : {}),
      }),
    });
  } catch {
    await AuthEventService.log({
      type: 'oauth_login_failed',
      req,
      metadata: { providerId: provider.id, reason: 'start_failed' },
    });

    return res.status(400).json({
      error: 'OAuth start failed',
    });
  }
}

export async function finishOAuthLogin(req: RouteRequest, res: Response) {
  const { providerId } = req.params;
  const { code, state } = req.body;
  const provider = await getOAuthProvider(providerId);

  if (!provider) {
    return res.status(404).json({ error: 'OAuth provider not found' });
  }

  const statePayload = consumeOAuthState(state, provider.id);

  if (!statePayload) {
    await AuthEventService.log({
      type: 'oauth_login_failed',
      req,
      metadata: { providerId: provider.id, reason: 'invalid_state' },
    });
    return res.status(400).json({ error: 'Invalid OAuth state' });
  }

  try {
    const { accessToken, idToken } = await exchangeOAuthTokens({
      provider,
      code,
      redirectUri: statePayload.redirectUri,
      codeVerifier: createOAuthPkceCodeVerifier(provider, statePayload),
    });
    const profile = isOidcProvider(provider)
      ? oauthProfileFromIdToken(
          provider,
          await verifyOAuthIdToken(provider, idToken, statePayload.nonce),
        )
      : await fetchOAuthProfile(provider, accessToken);
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
      subjectEmail: user.email,
      type: 'oauth_login_success',
      req,
      metadata: { providerId: provider.id },
    });

    const promptEnrollment =
      provider.promptPasskeyEnrollment &&
      (await Credential.count({ where: { userId: user.id } })) === 0;

    return issueSessionAndRespond({
      method: 'oauth',
      user: {
        id: user.id,
        email: user.email,
        phone: user.phone,
        roles: user.roles ?? [],
      },
      req,
      res,
      // Taken from the signed state rather than from this request, so it is the value
      // validated against the configured origins at /start and not one an attacker
      // introduced at the end of the round trip.
      extraFields: {
        ...(statePayload.returnTo ? { returnTo: statePayload.returnTo } : {}),
        ...(promptEnrollment ? { nextStep: 'enroll_passkey' } : {}),
      },
    });
  } catch (error) {
    if (error instanceof OAuthProviderRetiredError) {
      await AuthEventService.log({
        userId: error.userId,
        type: 'oauth_login_failed',
        req,
        metadata: {
          providerId: provider.id,
          reason: 'provider_retired',
          organizationIds: error.organizationIds,
        },
      });

      return res.status(403).json({ error: error.message, code: error.code });
    }

    logger.error(`OAuth callback failed for provider ${provider.id}: ${error}`);

    if (error instanceof OAuthProfileError) {
      await AuthEventService.log({
        type: 'oauth_login_failed',
        req,
        metadata: { providerId: provider.id, reason: error.code },
      });

      return res.status(400).json({
        error: error.message,
        code: error.code,
      });
    }

    await AuthEventService.log({
      type: 'oauth_login_failed',
      req,
      metadata: { providerId: provider.id, reason: 'callback_failed' },
    });

    return res.status(400).json({
      error: 'OAuth login failed',
    });
  }
}
