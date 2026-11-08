/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import {
  createWebhook,
  deleteWebhook,
  getWebhook,
  getWebhookDelivery,
  listWebhookDeliveries,
  listWebhooks,
  redeliverWebhook,
  rotateWebhookSecret,
  testWebhook,
  updateWebhook,
} from '../controllers/webhooks.js';
import { createRouter } from '../lib/createRouter.js';
import { requireAdmin } from '../middleware/requireAdmin.js';
import { requireStepUp } from '../middleware/requireStepUp.js';
import { ErrorSchema, MessageSchema } from '../schemas/generic.responses.js';
import { StepUpRequiredErrorSchema } from '../schemas/stepUp.responses.js';
import {
  CalloutTestResponseSchema,
  CreateWebhookEndpointRequestSchema,
  UpdateWebhookEndpointRequestSchema,
  WebhookDeliveryIdParamSchema,
  WebhookDeliveryListResponseSchema,
  WebhookDeliveryQuerySchema,
  WebhookDeliveryResponseSchema,
  WebhookEndpointCreatedResponseSchema,
  WebhookEndpointIdParamSchema,
  WebhookEndpointListResponseSchema,
  WebhookEndpointResponseSchema,
  WebhookSecretRotatedResponseSchema,
} from '../schemas/webhook.schemas.js';

/**
 * Signed, retried webhooks (ADR 0005). Sending a test event and redelivering are writes: each
 * makes a signed request to a URL an administrator chose, so they take step-up like the rest.
 */
const router = createRouter('/admin');

const tags = ['Admin', 'Webhooks'];
const read = { auth: 'access', tags, middleware: [requireAdmin('read')] };
const write = { auth: 'access', tags, middleware: [requireAdmin('write'), requireStepUp()] };

router.get(
  '/webhooks',
  {
    ...read,
    summary: 'List webhook endpoints',
    schemas: { response: { 200: WebhookEndpointListResponseSchema } },
  },
  listWebhooks,
);

router.post(
  '/webhooks',
  {
    ...write,
    summary: 'Create a webhook endpoint',
    description: 'Returns the signing secret once. It cannot be read back.',
    schemas: {
      body: CreateWebhookEndpointRequestSchema,
      response: {
        201: WebhookEndpointCreatedResponseSchema,
        400: ErrorSchema,
        403: StepUpRequiredErrorSchema,
        409: ErrorSchema,
      },
    },
  },
  createWebhook,
);

router.get(
  '/webhooks/:id',
  {
    ...read,
    summary: 'Get a webhook endpoint',
    schemas: {
      params: WebhookEndpointIdParamSchema,
      response: { 200: WebhookEndpointResponseSchema, 404: ErrorSchema },
    },
  },
  getWebhook,
);

router.patch(
  '/webhooks/:id',
  {
    ...write,
    summary: 'Update a webhook endpoint',
    description: 'Turning an endpoint back on clears why it was disabled.',
    schemas: {
      params: WebhookEndpointIdParamSchema,
      body: UpdateWebhookEndpointRequestSchema,
      response: {
        200: WebhookEndpointResponseSchema,
        400: ErrorSchema,
        403: StepUpRequiredErrorSchema,
        404: ErrorSchema,
      },
    },
  },
  updateWebhook,
);

router.delete(
  '/webhooks/:id',
  {
    ...write,
    summary: 'Delete a webhook endpoint',
    description: 'Also deletes its delivery history.',
    schemas: {
      params: WebhookEndpointIdParamSchema,
      response: { 200: MessageSchema, 403: StepUpRequiredErrorSchema, 404: ErrorSchema },
    },
  },
  deleteWebhook,
);

router.post(
  '/webhooks/:id/secret',
  {
    ...write,
    summary: 'Rotate a webhook signing secret',
    description:
      'Returns the new secret once. The previous one keeps signing beside it for 24 hours.',
    schemas: {
      params: WebhookEndpointIdParamSchema,
      response: {
        200: WebhookSecretRotatedResponseSchema,
        403: StepUpRequiredErrorSchema,
        404: ErrorSchema,
        409: ErrorSchema,
      },
    },
  },
  rotateWebhookSecret,
);

router.post(
  '/webhooks/:id/test',
  {
    ...write,
    summary: 'Send a test event',
    description: 'Sends `webhook.test` once, now, whatever the endpoint subscribes to.',
    schemas: {
      params: WebhookEndpointIdParamSchema,
      response: {
        200: CalloutTestResponseSchema,
        403: StepUpRequiredErrorSchema,
        404: ErrorSchema,
      },
    },
  },
  testWebhook,
);

router.get(
  '/webhook-deliveries',
  {
    ...read,
    summary: 'List webhook deliveries',
    description: 'Newest first. `status=dead` is the dead letter view. Kept for 30 days.',
    schemas: {
      query: WebhookDeliveryQuerySchema,
      response: { 200: WebhookDeliveryListResponseSchema, 400: ErrorSchema },
    },
  },
  listWebhookDeliveries,
);

router.get(
  '/webhook-deliveries/:deliveryId',
  {
    ...read,
    summary: 'Get a webhook delivery and its event',
    schemas: {
      params: WebhookDeliveryIdParamSchema,
      response: { 200: WebhookDeliveryResponseSchema, 404: ErrorSchema },
    },
  },
  getWebhookDelivery,
);

router.post(
  '/webhook-deliveries/:deliveryId/redeliver',
  {
    ...write,
    summary: 'Redeliver a webhook',
    description:
      'One attempt now, with the same `webhook-id` and body and a fresh timestamp and signature.',
    schemas: {
      params: WebhookDeliveryIdParamSchema,
      response: {
        200: WebhookDeliveryResponseSchema,
        403: StepUpRequiredErrorSchema,
        404: ErrorSchema,
      },
    },
  },
  redeliverWebhook,
);

export default router.router;
