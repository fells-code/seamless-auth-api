/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { NextFunction, Request, Response } from 'express';

import { Credential } from '../models/credentials.js';
import { TotpCredential } from '../models/totpCredentials.js';
import {
  findCurrentSession,
  FIRST_FACTOR_SIGN_IN_MAX_AGE_SECONDS,
  getStepUpStatusFromSession,
  serializeStepUpStatus,
} from '../services/stepUpService.js';
import { AuthenticatedRequest } from '../types/types.js';
import {
  DeviceStepUpAwareHandler,
  refuseDeviceSessionWithoutStepUp,
} from './requireDeviceSessionStepUp.js';

async function hasStepUpFactor(userId: string) {
  const [passkeys, totp] = await Promise.all([
    Credential.count({ where: { userId } }),
    TotpCredential.count({ where: { userId, enabled: true } }),
  ]);

  return passkeys > 0 || totp > 0;
}

function signedInRecently(authTime: Date | null | undefined, now = Date.now()) {
  if (!authTime) return false;

  return now - new Date(authTime).getTime() <= FIRST_FACTOR_SIGN_IN_MAX_AGE_SECONDS * 1000;
}

/**
 * For a route that adds something the account can sign in or step up with. An access token
 * alone is not enough: whoever holds a stolen one could add their own factor and keep the
 * account. An account that has a factor proves it with a fresh step-up, which only a factor
 * from before this sign-in can satisfy. An account with none has nothing to prove with, so
 * the sign-in itself must be recent. A recovery session exists to enrol and is let through.
 */
export const requireFactorEnrollmentProof: DeviceStepUpAwareHandler = async (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  if (refuseDeviceSessionWithoutStepUp(req, res)) return;

  const authReq = req as AuthenticatedRequest;
  if (authReq.recoverySession) return next();

  const userId = authReq.user?.id;
  const session =
    userId && authReq.sessionId ? await findCurrentSession(authReq.sessionId, userId) : null;

  if (!userId || !session) {
    res.status(401).json({ error: 'unauthorized' });
    return;
  }

  if (await hasStepUpFactor(userId)) {
    const status = getStepUpStatusFromSession(session);

    if (!status.fresh) {
      res.status(403).json({
        error: 'step_up_required',
        message: 'Recent step-up authentication is required',
        ...serializeStepUpStatus(status),
      });
      return;
    }

    return next();
  }

  if (!signedInRecently(session.authTime)) {
    res.status(403).json({
      error: 'reauthentication_required',
      message: 'Sign in again to add a sign-in method',
      maxAgeSeconds: FIRST_FACTOR_SIGN_IN_MAX_AGE_SECONDS,
    });
    return;
  }

  return next();
};

requireFactorEnrollmentProof.seamlessDeviceStepUp = true;
