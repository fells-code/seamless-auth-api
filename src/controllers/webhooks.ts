/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import type { WebhookDeliveryQuery } from '@seamless-auth/types';
import { Request, Response } from 'express';

import { AuthEventService } from '../services/authEventService.js';
import {
  createEndpoint,
  deleteEndpoint,
  getDelivery,
  getEndpoint,
  listDeliveries as listDeliveryRecords,
  listEndpoints,
  redeliver as redeliverRecord,
  rotateEndpointSecret,
  sendTestEvent,
  serializeDelivery,
  serializeEndpoint,
  updateEndpoint,
  WebhookError,
} from '../services/webhookService.js';
import { AuthenticatedRequest, RouteRequest } from '../types/types.js';

function actorUserId(req: Request) {
  return (req as AuthenticatedRequest).user?.id ?? null;
}

/**
 * The audit log is append-only, so a URL is recorded without its query string, where a receiver
 * may have put a token.
 */
function auditedUrl(url: string) {
  const parsed = new URL(url);
  return `${parsed.origin}${parsed.pathname}`;
}

function sendError(res: Response, error: unknown) {
  if (error instanceof WebhookError) {
    return res.status(error.status).json({ error: error.message });
  }

  throw error;
}

export async function listWebhooks(_req: Request, res: Response) {
  const endpoints = await listEndpoints();
  return res.json({ endpoints: endpoints.map(serializeEndpoint) });
}

export async function getWebhook(req: RouteRequest, res: Response) {
  try {
    return res.json({ endpoint: serializeEndpoint(await getEndpoint(req.params.id)) });
  } catch (error) {
    return sendError(res, error);
  }
}

export async function createWebhook(req: Request, res: Response) {
  try {
    const { endpoint, secret } = await createEndpoint(req.body, actorUserId(req));

    await AuthEventService.log({
      actorUserId: actorUserId(req),
      type: 'admin_webhook_created',
      req,
      metadata: {
        endpointId: endpoint.id,
        url: auditedUrl(endpoint.url),
        eventTypes: endpoint.eventTypes,
      },
    });

    return res.status(201).json({ endpoint: serializeEndpoint(endpoint), secret });
  } catch (error) {
    return sendError(res, error);
  }
}

export async function updateWebhook(req: RouteRequest, res: Response) {
  try {
    const endpoint = await updateEndpoint(req.params.id, req.body);

    await AuthEventService.log({
      actorUserId: actorUserId(req),
      type: 'admin_webhook_updated',
      req,
      metadata: { endpointId: endpoint.id, changed: Object.keys(req.body) },
    });

    return res.json({ endpoint: serializeEndpoint(endpoint) });
  } catch (error) {
    return sendError(res, error);
  }
}

export async function deleteWebhook(req: RouteRequest, res: Response) {
  try {
    const endpoint = await deleteEndpoint(req.params.id);

    await AuthEventService.log({
      actorUserId: actorUserId(req),
      type: 'admin_webhook_deleted',
      req,
      metadata: { endpointId: endpoint.id, url: auditedUrl(endpoint.url) },
    });

    return res.json({ message: 'Webhook deleted' });
  } catch (error) {
    return sendError(res, error);
  }
}

export async function rotateWebhookSecret(req: RouteRequest, res: Response) {
  try {
    const { endpoint, secret, previousSecretExpiresAt } = await rotateEndpointSecret(req.params.id);

    await AuthEventService.log({
      actorUserId: actorUserId(req),
      type: 'admin_webhook_secret_rotated',
      req,
      metadata: { endpointId: endpoint.id },
    });

    return res.json({ secret, previousSecretExpiresAt: previousSecretExpiresAt.toISOString() });
  } catch (error) {
    return sendError(res, error);
  }
}

export async function testWebhook(req: RouteRequest, res: Response) {
  try {
    return res.json(await sendTestEvent(req.params.id));
  } catch (error) {
    return sendError(res, error);
  }
}

export async function listWebhookDeliveries(req: Request, res: Response) {
  try {
    const { deliveries, nextCursor } = await listDeliveryRecords(
      req.query as unknown as WebhookDeliveryQuery,
    );
    return res.json({ deliveries: deliveries.map(serializeDelivery), nextCursor });
  } catch (error) {
    return sendError(res, error);
  }
}

export async function getWebhookDelivery(req: RouteRequest, res: Response) {
  try {
    const delivery = await getDelivery(req.params.deliveryId);
    return res.json({
      delivery: { ...serializeDelivery(delivery), event: JSON.parse(delivery.payload) },
    });
  } catch (error) {
    return sendError(res, error);
  }
}

export async function redeliverWebhook(req: RouteRequest, res: Response) {
  try {
    const delivery = await redeliverRecord(req.params.deliveryId);

    await AuthEventService.log({
      actorUserId: actorUserId(req),
      type: 'admin_webhook_redelivered',
      req,
      metadata: { deliveryId: delivery.id, endpointId: delivery.endpointId },
    });

    return res.json({
      delivery: { ...serializeDelivery(delivery), event: JSON.parse(delivery.payload) },
    });
  } catch (error) {
    return sendError(res, error);
  }
}
