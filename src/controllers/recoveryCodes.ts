/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { Request, Response } from 'express';

import { getSystemConfig } from '../config/getSystemConfig.js';
import { canReturnExternalDelivery } from '../lib/externalDelivery.js';
import { requireStepUp } from '../middleware/requireStepUp.js';
import { sendAccountNotice } from '../services/accountNotices.js';
import { AuthEventService } from '../services/authEventService.js';
import {
  generateRecoveryCodes,
  getRecoveryCodeStatus,
  redeemRecoveryCode,
} from '../services/recoveryCodeService.js';
import { issueSessionAndRespond } from '../services/sessionIssuance.js';
import { AuthenticatedRequest } from '../types/types.js';

async function recoveryCodesEnabled() {
  const { recovery_codes } = await getSystemConfig();
  return recovery_codes?.enabled !== false;
}

function refuseDisabled(res: Response) {
  return res.status(403).json({ error: 'recovery_codes_disabled' });
}

export const getRecoveryCodes = async (req: Request, res: Response) => {
  const { user } = req as AuthenticatedRequest;
  const status = await getRecoveryCodeStatus(user.id);

  return res.json({
    enabled: await recoveryCodesEnabled(),
    remaining: status.remaining,
    total: status.total,
    createdAt: status.createdAt ? status.createdAt.toISOString() : null,
  });
};

async function issueRecoveryCodes(req: Request, res: Response) {
  const { user } = req as AuthenticatedRequest;
  const { codes, createdAt } = await generateRecoveryCodes(user.id);

  await AuthEventService.log({ userId: user.id, type: 'recovery_codes_generated', req });

  return res.status(201).json({
    message: 'Success',
    codes,
    createdAt: createdAt.toISOString(),
  });
}

/**
 * A first set needs only the session. Replacing a set needs a fresh step-up, since it
 * invalidates codes the user may be relying on and hands whoever holds the session a way
 * back into the account.
 */
export const createRecoveryCodes = async (req: Request, res: Response) => {
  if (!(await recoveryCodesEnabled())) {
    return refuseDisabled(res);
  }

  const { user } = req as AuthenticatedRequest;
  const { total } = await getRecoveryCodeStatus(user.id);

  if (total === 0) {
    return issueRecoveryCodes(req, res);
  }

  return requireStepUp()(req, res, () => issueRecoveryCodes(req, res));
};

/**
 * Signs in with a recovery code. Not subject to lockout, like a passkey: a code cannot be
 * guessed under the flow rate limits, and lockout is exactly what someone recovering may
 * be locked out by. The session it issues is restricted until a new factor is enrolled.
 */
export const redeemRecoveryCodeLogin = async (req: Request, res: Response) => {
  if (!(await recoveryCodesEnabled())) {
    return refuseDisabled(res);
  }

  const { user } = req as AuthenticatedRequest;
  const redeemed = await redeemRecoveryCode(user.id, req.body.code);

  if (!redeemed) {
    await AuthEventService.log({ userId: user.id, type: 'recovery_code_failed', req });
    return res.status(401).json({ error: 'invalid_recovery_code' });
  }

  const { remaining } = await getRecoveryCodeStatus(user.id);
  const { app_name: name } = await getSystemConfig();
  const notices = await sendAccountNotice(
    user,
    {
      subject: `A recovery code was used on your ${name} account`,
      text:
        `A recovery code was used to sign in to your ${name} account (${remaining} left). ` +
        'If this was not you, contact your administrator.',
    },
    { external: await canReturnExternalDelivery(req) },
  );

  await AuthEventService.log({
    userId: user.id,
    type: 'recovery_code_used',
    req,
    metadata: { remaining, notices },
  });

  await issueSessionAndRespond({
    method: 'recovery_code',
    recovery: true,
    user: {
      id: user.id,
      email: user.email,
      phone: user.phone,
      roles: user.roles ?? [],
    },
    req,
    res,
  });
};
