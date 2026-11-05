/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { NextFunction, Request, RequestHandler, Response } from 'express';

import { getStepUpStatusFromSession, serializeStepUpStatus } from '../services/stepUpService.js';
import { AuthenticatedRequest } from '../types/types.js';

/** Marks a middleware that can answer `403 step_up_required`, so `defineRoute` documents it. */
export type DeviceStepUpAwareHandler = RequestHandler & { seamlessDeviceStepUp?: true };

/**
 * ADR 0003, X7. Someone who phished a device approval holds a session from a device grant
 * without holding the user's factor (RFC 8628 section 5.4). This answers for them until that
 * session has a fresh step-up of its own, and answers nothing for any other session.
 *
 * @returns whether a refusal was sent.
 */
export function refuseDeviceSessionWithoutStepUp(req: Request, res: Response): boolean {
  const { deviceChildSession } = req as AuthenticatedRequest;
  if (!deviceChildSession) return false;

  const status = getStepUpStatusFromSession(deviceChildSession);
  if (status.fresh) return false;

  res.status(403).json({
    error: 'step_up_required',
    message: 'Recent step-up authentication is required',
    ...serializeStepUpStatus(status),
  });
  return true;
}

/**
 * For a route that changes how the account signs in or recovers. Anything a session from a
 * device grant could add here, it could then authenticate with, so without this an attacker's
 * own TOTP would satisfy every other step-up on the instance. A new route of that kind opts in
 * by listing this first in its `middleware`.
 */
export const requireDeviceSessionStepUp: DeviceStepUpAwareHandler = (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  if (!refuseDeviceSessionWithoutStepUp(req, res)) next();
};

requireDeviceSessionStepUp.seamlessDeviceStepUp = true;
