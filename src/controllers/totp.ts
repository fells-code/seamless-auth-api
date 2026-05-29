/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { Request, Response } from 'express';

import { getSystemConfig } from '../config/getSystemConfig.js';
import { AuthEventService } from '../services/authEventService.js';
import { issueSessionAndRespond } from '../services/sessionIssuance.js';
import { recordStepUpVerification, serializeStepUpStatus } from '../services/stepUpService.js';
import {
  disableTotp,
  getTotpStatus,
  startTotpEnrollment,
  verifyEnabledTotp,
  verifyTotpEnrollment,
} from '../services/totpService.js';
import { AuthenticatedRequest } from '../types/types.js';
import getLogger from '../utils/logger.js';

const logger = getLogger('totp');

function serializeDate(value: Date | null) {
  return value?.toISOString() ?? null;
}

function getAuthenticatedUser(req: Request) {
  return (req as AuthenticatedRequest).user;
}

export const getCurrentTotpStatus = async (req: Request, res: Response) => {
  const user = getAuthenticatedUser(req);

  if (!user?.id) {
    return res.status(401).json({ error: 'unauthorized' });
  }

  const status = await getTotpStatus(user.id);

  return res.json({
    enabled: status.enabled,
    verifiedAt: serializeDate(status.verifiedAt),
    lastUsedAt: serializeDate(status.lastUsedAt),
  });
};

export const startCurrentTotpEnrollment = async (req: Request, res: Response) => {
  const user = getAuthenticatedUser(req);

  if (!user?.id || !user.email) {
    await AuthEventService.log({
      userId: user?.id ?? null,
      type: 'totp_suspicious',
      req,
      metadata: { reason: 'Missing authenticated user or email' },
    });
    return res.status(401).json({ error: 'unauthorized' });
  }

  try {
    const { app_name } = await getSystemConfig();
    const enrollment = await startTotpEnrollment({
      userId: user.id,
      email: user.email,
      issuer: app_name || 'Seamless Auth',
    });

    await AuthEventService.log({
      userId: user.id,
      type: 'totp_enrollment_started',
      req,
    });

    return res.status(200).json({
      message: 'Success',
      ...enrollment,
    });
  } catch (error) {
    logger.error(`Failed to start TOTP enrollment: ${error}`);
    await AuthEventService.log({
      userId: user.id,
      type: 'totp_failed',
      req,
      metadata: { reason: 'Enrollment start failed' },
    });
    return res.status(500).json({ error: 'Internal server error' });
  }
};

export const verifyCurrentTotpEnrollment = async (req: Request, res: Response) => {
  const user = getAuthenticatedUser(req);
  const { code } = req.body;

  if (!user?.id) {
    return res.status(401).json({ error: 'unauthorized' });
  }

  const result = await verifyTotpEnrollment(user.id, code);

  if (!result.verified) {
    await AuthEventService.log({
      userId: user.id,
      type: 'totp_failed',
      req,
      metadata: { reason: result.reason },
    });
    return res.status(401).json({ error: 'totp_verification_failed' });
  }

  await AuthEventService.log({
    userId: user.id,
    type: 'totp_enrollment_success',
    req,
  });

  return res.json({ message: 'Success' });
};

export const disableCurrentTotp = async (req: Request, res: Response) => {
  const user = getAuthenticatedUser(req);
  const { code } = req.body;

  if (!user?.id) {
    return res.status(401).json({ error: 'unauthorized' });
  }

  const result = await disableTotp(user.id, code);

  if (!result.disabled) {
    await AuthEventService.log({
      userId: user.id,
      type: 'totp_failed',
      req,
      metadata: { reason: result.reason },
    });
    return res.status(401).json({ error: 'totp_disable_failed' });
  }

  await AuthEventService.log({
    userId: user.id,
    type: 'totp_disabled',
    req,
  });

  return res.json({ message: 'Success' });
};

export const verifyTotpLogin = async (req: Request, res: Response) => {
  const user = getAuthenticatedUser(req);
  const { code } = req.body;

  if (!user?.id) {
    await AuthEventService.log({
      userId: null,
      type: 'totp_suspicious',
      req,
      metadata: { reason: 'Missing pre-authenticated user' },
    });
    return res.status(401).json({ error: 'unauthorized' });
  }

  const result = await verifyEnabledTotp(user.id, code);

  if (!result.verified) {
    await AuthEventService.log({
      userId: user.id,
      type: 'totp_failed',
      req,
      metadata: { reason: result.reason, flow: 'login' },
    });
    return res.status(401).json({ error: 'totp_verification_failed' });
  }

  await AuthEventService.log({
    userId: user.id,
    type: 'totp_success',
    req,
    metadata: { flow: 'login' },
  });

  await issueSessionAndRespond({
    user: {
      id: user.id,
      email: user.email,
      phone: user.phone,
      roles: user.roles ?? [],
    },
    req,
    res,
  });

  await user.update({
    lastLogin: new Date(),
  });
};

export const verifyTotpMfa = async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const user = authReq.user;
  const { code } = req.body;

  if (!user?.id || !authReq.sessionId) {
    return res.status(401).json({ error: 'unauthorized' });
  }

  const result = await verifyEnabledTotp(user.id, code);

  if (!result.verified) {
    await AuthEventService.log({
      userId: user.id,
      type: 'mfa_otp_failed',
      req,
      metadata: { reason: result.reason, method: 'totp' },
    });
    return res.status(401).json({ error: 'totp_verification_failed' });
  }

  const status = await recordStepUpVerification({
    sessionId: authReq.sessionId,
    userId: user.id,
    method: 'totp',
  });

  if (!status) {
    return res.status(401).json({ error: 'unauthorized' });
  }

  await AuthEventService.log({
    userId: user.id,
    type: 'mfa_otp_success',
    req,
    metadata: { method: 'totp' },
  });

  return res.json({
    message: 'Success',
    ...serializeStepUpStatus(status),
    method: 'totp',
  });
};
