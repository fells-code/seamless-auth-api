/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import {
  deleteHook,
  getHook,
  listHookInvocations,
  listHooks,
  rotateHookSecret,
  setHook,
  testHook,
} from '../controllers/loginHooks.js';
import { createRouter } from '../lib/createRouter.js';
import { requireAdmin } from '../middleware/requireAdmin.js';
import { requireStepUp } from '../middleware/requireStepUp.js';
import { ErrorSchema, MessageSchema } from '../schemas/generic.responses.js';
import {
  CalloutTestResponseSchema,
  LoginHookInvocationListResponseSchema,
  LoginHookInvocationQuerySchema,
  LoginHookListResponseSchema,
  LoginHookResponseSchema,
  LoginHookSecretRotatedResponseSchema,
  LoginHookTriggerParamSchema,
  SetLoginHookRequestSchema,
} from '../schemas/loginHook.schemas.js';
import { StepUpRequiredErrorSchema } from '../schemas/stepUp.responses.js';

/**
 * Login hooks (ADR 0005, E5). A test call is a write like the rest: it makes a signed request to
 * a URL an administrator chose.
 */
const router = createRouter('/admin');

const tags = ['Admin', 'Login hooks'];
const read = { auth: 'access', tags, middleware: [requireAdmin('read')] };
const write = { auth: 'access', tags, middleware: [requireAdmin('write'), requireStepUp()] };

router.get(
  '/login-hooks',
  {
    ...read,
    summary: 'List login hooks',
    schemas: { response: { 200: LoginHookListResponseSchema } },
  },
  listHooks,
);

router.put(
  '/login-hooks/:trigger',
  {
    ...write,
    summary: "Create or replace a trigger's login hook",
    description:
      'Returns the signing secret once, when this call creates the hook. Replacing a hook keeps its secret.',
    schemas: {
      params: LoginHookTriggerParamSchema,
      body: SetLoginHookRequestSchema,
      response: {
        200: LoginHookResponseSchema,
        201: LoginHookResponseSchema,
        400: ErrorSchema,
        403: StepUpRequiredErrorSchema,
        409: ErrorSchema,
      },
    },
  },
  setHook,
);

router.get(
  '/login-hooks/:trigger',
  {
    ...read,
    summary: "Get a trigger's login hook",
    schemas: {
      params: LoginHookTriggerParamSchema,
      response: { 200: LoginHookResponseSchema, 404: ErrorSchema },
    },
  },
  getHook,
);

router.delete(
  '/login-hooks/:trigger',
  {
    ...write,
    summary: "Delete a trigger's login hook",
    schemas: {
      params: LoginHookTriggerParamSchema,
      response: { 200: MessageSchema, 403: StepUpRequiredErrorSchema, 404: ErrorSchema },
    },
  },
  deleteHook,
);

router.post(
  '/login-hooks/:trigger/secret',
  {
    ...write,
    summary: 'Rotate a login hook signing secret',
    description:
      'Returns the new secret once. The previous one keeps signing beside it for 24 hours.',
    schemas: {
      params: LoginHookTriggerParamSchema,
      response: {
        200: LoginHookSecretRotatedResponseSchema,
        403: StepUpRequiredErrorSchema,
        404: ErrorSchema,
        409: ErrorSchema,
      },
    },
  },
  rotateHookSecret,
);

router.post(
  '/login-hooks/:trigger/test',
  {
    ...write,
    summary: 'Send a test call to a login hook',
    description:
      'One signed call with a placeholder user. Succeeds when the hook answers 2xx with a body its trigger accepts.',
    schemas: {
      params: LoginHookTriggerParamSchema,
      response: {
        200: CalloutTestResponseSchema,
        403: StepUpRequiredErrorSchema,
        404: ErrorSchema,
      },
    },
  },
  testHook,
);

router.get(
  '/login-hooks/:trigger/invocations',
  {
    ...read,
    summary: 'List login hook invocations',
    description: 'Newest first. Kept for 30 days.',
    schemas: {
      params: LoginHookTriggerParamSchema,
      query: LoginHookInvocationQuerySchema,
      response: { 200: LoginHookInvocationListResponseSchema, 400: ErrorSchema },
    },
  },
  listHookInvocations,
);

export default router.router;
