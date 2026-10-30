/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { Request, Response } from 'express';

import { isBreakGlassAdmin } from '../config/breakGlass.js';
import { getSystemConfig } from '../config/getSystemConfig.js';
import { createRefreshTokenLookup, generateRefreshToken, signAccessToken } from '../lib/token.js';
import { Session, SessionAuthMethod } from '../models/sessions.js';
import { computeSessionTimes, parseDurationToSeconds } from '../utils/utils.js';
import { enforceConcurrentSessionLimit } from './concurrentSessionPolicy.js';
import { isPasskeyRequiredForUser } from './loginPolicyService.js';
import { getDefaultOrganizationIdForUser } from './organizationService.js';

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

export async function issueSessionAndRespond(params: IssueSessionParams): Promise<void> {
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
  // policy says. A recovery session is exempt: enrolling a passkey is all it can do.
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
  const organizationId = await getDefaultOrganizationIdForUser(user.id);

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
  });

  const token = await signAccessToken(session.id, user.id, user.roles, organizationId, {
    recovery,
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
}
