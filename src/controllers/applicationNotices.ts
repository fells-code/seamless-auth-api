/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import type { SendApplicationNoticeRequest } from '@seamless-auth/types';
import { Response } from 'express';

import { getSystemConfig } from '../config/getSystemConfig.js';
import { acceptedDeliveryKinds, canReturnExternalDelivery } from '../lib/externalDelivery.js';
import type { ApplicationRequest } from '../middleware/requireApplicationToken.js';
import { ownerWasNotified } from '../services/accountNotices.js';
import {
  ApplicationNoticeError,
  sendApplicationNotice,
} from '../services/applicationNoticeService.js';
import { AuthEventService } from '../services/authEventService.js';

export async function sendApplicationNoticeHandler(req: ApplicationRequest, res: Response) {
  const client = req.oidcClient!;
  const body = req.body as SendApplicationNoticeRequest;
  const external = await canReturnExternalDelivery(req);
  const instanceName = (await getSystemConfig()).app_name ?? 'Seamless Auth';

  let sent;
  try {
    sent = await sendApplicationNotice(client, instanceName, body, {
      external,
      returnable: external ? acceptedDeliveryKinds(req) : undefined,
    });
  } catch (error) {
    if (!(error instanceof ApplicationNoticeError)) throw error;

    await AuthEventService.log({
      type: 'oidc_account_notice_failed',
      req,
      metadata: { clientId: client.id, reason: error.code },
    });
    return res.status(error.status).json({ error: error.code });
  }

  const { outcome } = sent;
  const channels = outcome.results.map(({ channel, status }) => ({
    channel: channel === 'phone' ? ('sms' as const) : ('email' as const),
    status,
  }));

  const audit = { userId: sent.userId, req, metadata: { clientId: client.id, channels } };

  if (ownerWasNotified(outcome)) {
    await AuthEventService.log({ ...audit, type: 'oidc_account_notice_sent' });
  } else {
    await AuthEventService.log({ ...audit, type: 'oidc_account_notice_failed' });
  }

  return res.status(200).json({
    channels,
    ...(outcome.deliveries.length ? { deliveries: outcome.deliveries } : {}),
  });
}
