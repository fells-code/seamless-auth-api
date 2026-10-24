/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { Request, Response } from 'express';

import { getSystemConfig } from '../config/getSystemConfig.js';
import { canReturnExternalDelivery } from '../lib/externalDelivery.js';
import { RecoveryChannel } from '../models/accountRecoveryRequests.js';
import { sendAccountNotice, verifiedAddresses } from '../services/accountNotices.js';
import {
  cancelRecoveryByToken,
  completeRecovery,
  findRecoveryForAttempt,
  isAccountRecoveryAvailable,
  RecoveryStatus,
  recoveryStatus,
  startRecovery,
  verifyRecovery,
} from '../services/accountRecoveryService.js';
import { AuthEventService } from '../services/authEventService.js';
import { DeliveryError } from '../services/deliveryError.js';
import { sendOTPEmail, sendOTPSMS } from '../services/messagingService.js';
import { issueSessionAndRespond } from '../services/sessionIssuance.js';
import { AuthenticatedRequest } from '../types/types.js';
import getLogger from '../utils/logger.js';
import { normalizePhoneNumber, parseDurationToSeconds } from '../utils/utils.js';

const logger = getLogger('accountRecovery');

export const RECOVERY_STARTED_MESSAGE =
  'If the account has a verified address for that channel, a recovery code was sent.';
export const RECOVERY_CANCEL_MESSAGE =
  'If the link was for an open recovery request, it has been cancelled.';

export async function accountRecoveryPolicy() {
  const config = await getSystemConfig();
  const { account_recovery } = config;

  return {
    enabled: isAccountRecoveryAvailable(config),
    delaySeconds: parseDurationToSeconds(account_recovery?.delay ?? '24h'),
  };
}

export function refuseAccountRecoveryDisabled(res: Response) {
  return res.status(403).json({ error: 'account_recovery_disabled' });
}

export function serializeRecoveryStatus(status: RecoveryStatus) {
  return {
    state: status.state,
    requestedAt: status.requestedAt.toISOString(),
    completesAt: status.completesAt.toISOString(),
  };
}

function recoveryAddress(user: AuthenticatedRequest['user'], channel: RecoveryChannel) {
  const { email, phone } = verifiedAddresses(user);

  return channel === 'email' ? email : phone ? normalizePhoneNumber(phone) : null;
}

async function appName() {
  return (await getSystemConfig())?.app_name ?? 'Seamless Auth';
}

async function cancelUrl(cancelToken: string) {
  const { frontend_url, origins } = await getSystemConfig();
  const base = (frontend_url ?? origins?.[0] ?? '').replace(/\/+$/, '');

  // A fragment, so the token never reaches a server log on the way to the page.
  return `${base}/recovery/cancel#${cancelToken}`;
}

/**
 * Sends a code to the verified address on the chosen channel. Answers the same whether
 * or not the account has one, so it does not say which channels an account has.
 * Account lockout does not apply: lockout is what someone recovering may be locked out by.
 */
export const startAccountRecovery = async (req: Request, res: Response) => {
  if (!(await accountRecoveryPolicy()).enabled) {
    return refuseAccountRecoveryDisabled(res);
  }

  const { user, attemptId } = req as AuthenticatedRequest;
  const channel: RecoveryChannel = req.body?.channel ?? 'email';
  const to = recoveryAddress(user, channel);

  if (!to || !attemptId) {
    await AuthEventService.log({
      userId: user.id,
      type: 'account_recovery_started',
      req,
      metadata: { channel, sent: false, reason: 'No verified address' },
    });
    return res.status(200).json({ message: RECOVERY_STARTED_MESSAGE });
  }

  const external = await canReturnExternalDelivery(req);

  try {
    const code = await startRecovery(user.id, channel, attemptId);

    if (!external) {
      if (channel === 'email') {
        await sendOTPEmail(to, code);
      } else {
        await sendOTPSMS(to, Number(code));
      }
    }

    await AuthEventService.log({
      userId: user.id,
      type: 'account_recovery_started',
      req,
      metadata: { channel, sent: true },
    });

    return res.status(200).json({
      message: RECOVERY_STARTED_MESSAGE,
      ...(external
        ? {
            delivery:
              channel === 'email'
                ? { kind: 'otp_email', to, token: code }
                : { kind: 'otp_sms', to, token: code },
          }
        : {}),
    });
  } catch (error) {
    if (!(error instanceof DeliveryError)) throw error;

    logger.error(
      `Account recovery code delivery failed on ${channel === 'email' ? 'email' : 'phone'}`,
    );
    await AuthEventService.log({
      userId: user.id,
      type: 'account_recovery_failed',
      req,
      metadata: { channel, reason: 'Delivery failed' },
    });
    return res.status(500).json({ error: 'Internal server error' });
  }
};

async function openedNotice(channel: RecoveryChannel, completesAt: Date, cancelToken: string) {
  const name = await appName();
  const link = await cancelUrl(cancelToken);
  const via = channel === 'email' ? 'email address' : 'phone number';
  const text =
    `Someone asked to recover your ${name} account through its ${via}. Unless it is ` +
    `cancelled, recovery completes at ${completesAt.toISOString()}, signs out every ` +
    `session and lets them enroll a new passkey. If this was not you, cancel it: ${link}`;

  return { subject: `Account recovery requested for your ${name} account`, text };
}

/**
 * Opens the request with the code from `/recovery/start`, starting its delay and telling
 * every verified address how to cancel it. A code for an open request resumes it on this
 * attempt instead, with its clock unchanged.
 */
export const verifyAccountRecovery = async (req: Request, res: Response) => {
  const { enabled, delaySeconds } = await accountRecoveryPolicy();

  if (!enabled) {
    return refuseAccountRecoveryDisabled(res);
  }

  const { user, attemptId } = req as AuthenticatedRequest;
  const result = attemptId
    ? await verifyRecovery(user.id, attemptId, req.body.code, delaySeconds)
    : ({ outcome: 'invalid' } as const);

  if (result.outcome === 'invalid') {
    await AuthEventService.log({
      userId: user.id,
      type: 'account_recovery_failed',
      req,
      metadata: { reason: 'Invalid code' },
    });
    return res.status(401).json({ error: 'invalid_recovery_code' });
  }

  const { request } = result;
  const status = recoveryStatus(request);

  if (result.outcome === 'resumed') {
    await AuthEventService.log({
      userId: user.id,
      type: 'account_recovery_verified',
      req,
      metadata: { channel: request.channel, resumed: true },
    });
    return res.status(200).json(serializeRecoveryStatus(status));
  }

  const notices = await sendAccountNotice(
    user,
    await openedNotice(request.channel, status.completesAt, result.cancelToken),
    { external: await canReturnExternalDelivery(req) },
  );

  await AuthEventService.log({
    userId: user.id,
    type: 'account_recovery_verified',
    req,
    metadata: {
      channel: request.channel,
      completesAt: status.completesAt.toISOString(),
      supersededRequests: result.cancelled,
      notices,
    },
  });

  return res.status(200).json(serializeRecoveryStatus(status));
};

export const getAccountRecoveryStatus = async (req: Request, res: Response) => {
  if (!(await accountRecoveryPolicy()).enabled) {
    return refuseAccountRecoveryDisabled(res);
  }

  const { user, attemptId } = req as AuthenticatedRequest;
  const request = attemptId ? await findRecoveryForAttempt(user.id, attemptId) : null;

  if (!request) {
    return res.status(404).json({ error: 'recovery_not_found' });
  }

  return res.status(200).json(serializeRecoveryStatus(recoveryStatus(request)));
};

/**
 * Public on purpose: the token is the credential, and the owner may be signed out
 * everywhere. Answers the same whether or not it matched, so it is not an oracle.
 */
// Not gated on the feature being available: turning recovery off, or switching to
// phishing-resistant-only mode, must not stop an owner cancelling a request already open.
export const cancelAccountRecovery = async (req: Request, res: Response) => {
  const cancelToken = req.body?.cancelToken;

  if (typeof cancelToken !== 'string' || cancelToken.length === 0) {
    return res.status(400).json({ error: 'cancel_token_required' });
  }

  const request = await cancelRecoveryByToken(cancelToken);

  if (request) {
    await AuthEventService.log({
      userId: request.userId,
      type: 'account_recovery_cancelled',
      req,
      metadata: { channel: request.channel, via: 'cancel_token' },
    });
  }

  return res.status(200).json({ message: RECOVERY_CANCEL_MESSAGE });
};

/**
 * Completes a request whose delay has passed: signs out every session, tells every
 * verified address, and issues a recovery session that can only enroll a new factor.
 */
export const completeAccountRecovery = async (req: Request, res: Response) => {
  if (!(await accountRecoveryPolicy()).enabled) {
    return refuseAccountRecoveryDisabled(res);
  }

  const { user, attemptId } = req as AuthenticatedRequest;
  const result = attemptId ? await completeRecovery(user.id, attemptId) : null;

  if (!result || result.outcome === 'not_found') {
    return res.status(404).json({ error: 'recovery_not_found' });
  }

  if (result.outcome === 'not_ready') {
    return res.status(409).json({
      error: 'recovery_not_ready',
      message: `Recovery completes at ${(result.request.completesAt as Date).toISOString()}`,
    });
  }

  const name = await appName();
  const notices = await sendAccountNotice(
    user,
    {
      subject: `Your ${name} account was recovered`,
      text:
        `Your ${name} account was recovered and every session on it was signed out. ` +
        'If this was not you, contact your administrator.',
    },
    { external: await canReturnExternalDelivery(req) },
  );

  await AuthEventService.log({
    userId: user.id,
    type: 'account_recovery_completed',
    req,
    metadata: {
      channel: result.request.channel,
      revokedSessions: result.revokedSessions,
      notices,
    },
  });

  await issueSessionAndRespond({
    method: 'account_recovery',
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
