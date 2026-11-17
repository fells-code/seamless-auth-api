/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { Request, Response } from 'express';

import { isBreakGlassAdmin } from '../config/breakGlass.js';
import { getSystemConfig } from '../config/getSystemConfig.js';
import { createRefreshTokenLookup, generateRefreshToken } from '../lib/token.js';
import { Session, SessionAuthMethod } from '../models/sessions.js';
import { computeSessionTimes, parseDurationToSeconds } from '../utils/utils.js';
import { mintAccessToken } from './accessTokenService.js';
import { AuthEventService } from './authEventService.js';
import { enforceConcurrentSessionLimit } from './concurrentSessionPolicy.js';
import {
  type HookClaims,
  type LoginHookContext,
  type LoginHookRefusal,
  loginHookRefusal,
  runLoginHook,
  verdictClaims,
} from './loginHookService.js';
import { isPasskeyRequiredForUser } from './loginPolicyService.js';
import { getDefaultOrganizationIdForUser } from './organizationService.js';
import { hardRevokeSession } from './sessionService.js';

/** The factor that proved the user, as far as session issuance needs to know it. */
export type SessionMethod =
  | 'passkey'
  | 'email_otp'
  | 'phone_otp'
  | 'magic_link'
  | 'totp'
  | 'oauth'
  | 'recovery_code'
  | 'account_recovery';

function recordAuthMethod(
  method: SessionMethod,
  at: Date,
  passkey: IssueSessionParams['passkey'],
): SessionAuthMethod[] {
  // Account recovery proves an address, not a factor, so it earns no amr.
  if (method === 'account_recovery') return [];

  return [{ method, at: at.toISOString(), ...(method === 'passkey' ? passkey : {}) }];
}

export class PasskeyRequiredError extends Error {
  constructor(method: SessionMethod) {
    super(`Refused to issue a session from ${method}: this sign-in has to be a passkey`);
    this.name = 'PasskeyRequiredError';
  }
}

export class BreakGlassFactorError extends Error {
  constructor(method: SessionMethod) {
    super(`Refused to issue a break-glass admin session from ${method}`);
    this.name = 'BreakGlassFactorError';
  }
}

const BREAK_GLASS_FACTORS: ReadonlySet<SessionMethod> = new Set([
  'passkey',
  'totp',
  'recovery_code',
]);

type IssueSessionParams = {
  method: SessionMethod;
  /**
   * The session that completes a new account's address verification. The one session a
   * non-passkey factor may start in phishing-resistant-only mode, because the account has
   * nothing else to sign in with until its first passkey is enrolled.
   */
  accountVerification?: boolean;
  /**
   * A session for someone who proved the account another way after losing their factors.
   * Restricted until they enroll a new one, so policy that removes their other sign-in
   * methods does not apply: this is how they get one back.
   */
  recovery?: boolean;
  /** What the authenticator reported, for a passkey sign-in. Feeds the provider's acr and amr. */
  passkey?: { deviceBound: boolean; userVerified: boolean };
  user: {
    id: string;
    email: string;
    phone: string | null;
    roles: string[];
  };
  req: Request;
  res: Response;
  /**
   * Fields the calling flow adds to the session response.
   *
   * Kept generic rather than naming OAuth's `returnTo` here, so session issuance does
   * not have to know which flow reached it. Each route validates its own response
   * against its declared schema, which is what keeps this from becoming a way to put
   * anything at all in the body.
   */
  extraFields?: Record<string, unknown>;
};

async function runSignInHooks(
  context: LoginHookContext,
): Promise<{ claims: HookClaims | null } | { refusal: LoginHookRefusal }> {
  const postLoginRefusal = loginHookRefusal(await runLoginHook('post_login', context));
  if (postLoginRefusal) return { refusal: postLoginRefusal };

  const preToken = await runLoginHook('pre_token', context);
  const preTokenRefusal = loginHookRefusal(preToken);
  if (preTokenRefusal) return { refusal: preTokenRefusal };

  return { claims: verdictClaims(preToken) };
}

/**
 * Answers the request either way. Resolves false when a login hook refused the sign-in, so the
 * caller stops before anything it does only for a completed sign-in.
 */
export async function issueSessionAndRespond(params: IssueSessionParams): Promise<boolean> {
  const {
    user,
    req,
    res,
    extraFields,
    method,
    accountVerification,
    recovery = false,
    passkey,
  } = params;

  // Every endpoint that reaches here with another factor refuses first, with a 403. This
  // is the backstop for one that does not, so it fails closed rather than trusting the
  // gates. It covers both rules, phishing-resistant-only mode and an account that holds a
  // passkey while fallback is off, because OAuth once shipped without the second. A
  // break-glass admin is held to its own rule instead: a strong factor, whatever the
  // policy says. A recovery session is exempt: enrolling a factor is all it can do.
  const breakGlass = isBreakGlassAdmin(user);

  if (breakGlass && !accountVerification && !BREAK_GLASS_FACTORS.has(method)) {
    throw new BreakGlassFactorError(method);
  }

  if (
    !breakGlass &&
    method !== 'passkey' &&
    !accountVerification &&
    !recovery &&
    (await isPasskeyRequiredForUser(user.id))
  ) {
    throw new PasskeyRequiredError(method);
  }

  const organizationId = await getDefaultOrganizationIdForUser(user.id);
  let hookClaims: Record<string, unknown> | null = null;

  // A hook that is down must not lock out the administrator who would fix it. A recovery
  // session runs the hooks when its restriction lifts instead (see
  // `liftRecoveryRestrictionAfterHooks`). Both run before the concurrent session limit, so a
  // refused sign-in cannot cost the user a session they already had.
  if (!breakGlass && !recovery) {
    const outcome = await runSignInHooks({ user, method, organizationId, req });
    if ('refusal' in outcome) {
      res.status(outcome.refusal.status).json(outcome.refusal.body);
      return false;
    }
    hookClaims = outcome.claims;
  }

  const refreshToken = generateRefreshToken();
  const refreshTokenLookup = createRefreshTokenLookup(refreshToken);
  const { access_token_ttl, refresh_token_ttl, session_idle_ttl, max_concurrent_sessions } =
    await getSystemConfig();
  const now = new Date();
  const { expiresAt, idleExpiresAt } = computeSessionTimes(
    {
      absoluteTtl: refresh_token_ttl || '1d',
      idleTtl: session_idle_ttl || '8h',
    },
    now,
  );

  // Before the row exists, so the limit counts the session about to be created.
  await enforceConcurrentSessionLimit({
    userId: user.id,
    limit: max_concurrent_sessions,
    req,
  });

  const session = await Session.create({
    userId: user.id,
    infraId: process.env.APP_ID!,
    organizationId,
    mode: 'server',
    refreshTokenLookup,
    userAgent: req.get('user-agent'),
    ipAddress: req.ip,
    expiresAt,
    idleExpiresAt,
    chainStartedAt: now,
    lastUsedAt: undefined,
    recovery,
    authMethods: recordAuthMethod(method, now, passkey),
    authTime: now,
    hookClaims,
  });

  const { token } = await mintAccessToken({
    session: { id: session.id, organizationId, recovery, hookClaims },
    user,
  });

  // The one record that a sign-in completed, whatever the factor: the factor events before it
  // can be steps of a flow that still fails. The `user.signed_in` webhook is built from it.
  await AuthEventService.log({
    userId: user.id,
    sessionId: session.id,
    type: 'session_created',
    req,
    metadata: { method, organizationId, ...(recovery ? { recovery: true } : {}) },
  });

  if (!token || !refreshToken) {
    throw new Error('Failed to issue session tokens');
  }

  res.status(200).json({
    // Spread first so a flow that adds to the response cannot replace any part of the
    // session in it. The bag is untyped by design, and the fields below are the ones a
    // caller authenticates with.
    ...extraFields,
    message: 'Success',
    token,
    refreshToken,
    sub: user.id,
    organizationId,
    roles: user.roles,
    email: user.email,
    phone: user.phone,
    ttl: parseDurationToSeconds(access_token_ttl || '15m'),
    refreshTtl: parseDurationToSeconds(refresh_token_ttl || '1d'),
    ...(recovery ? { recovery: true, nextStep: 'enroll_passkey' } : {}),
  });

  return true;
}

export const RECOVERY_HOOK_REFUSED = 'recovery_login_hook_refused';

/**
 * Ends a recovery session's restriction once the user has enrolled a factor of their own.
 * The session was issued without the login hooks, so they run here, the first point at which
 * it can do more than enroll. A refusal revokes the session rather than leaving it restricted:
 * the factor just enrolled is kept, and signing in with it runs the hooks again.
 *
 * Resolves the refusal for the caller to answer with, or null when the session is now
 * unrestricted (or was not a recovery session to begin with).
 */
export async function liftRecoveryRestrictionAfterHooks(params: {
  sessionId: string | undefined;
  user: { id: string; email: string; phone: string | null; roles?: string[] };
  req: Request;
}): Promise<LoginHookRefusal | null> {
  const { sessionId, req } = params;
  const { id, email, phone, roles } = params.user;
  const user = { id, email, phone, roles: roles ?? [] };
  if (!sessionId) return null;

  const session = await Session.findOne({
    where: { id: sessionId, userId: user.id, recovery: true, revokedAt: null },
  });
  if (!session) return null;

  let hookClaims: HookClaims | null = null;

  if (!isBreakGlassAdmin(user)) {
    const outcome = await runSignInHooks({
      user,
      method: session.authMethods?.[0]?.method ?? 'account_recovery',
      organizationId: session.organizationId ?? null,
      req,
    });

    if ('refusal' in outcome) {
      await hardRevokeSession(session, RECOVERY_HOOK_REFUSED);
      return outcome.refusal;
    }
    hookClaims = outcome.claims;
  }

  await Session.update(
    { recovery: false, hookClaims },
    { where: { id: session.id, recovery: true, revokedAt: null } },
  );

  return null;
}
