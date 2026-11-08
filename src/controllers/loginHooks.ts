/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import type { LoginHookInvocationQuery, LoginHookTrigger } from '@seamless-auth/types';
import { Request, Response } from 'express';

import { AuthEventService } from '../services/authEventService.js';
import {
  deleteLoginHook,
  getLoginHook,
  listInvocations,
  listLoginHooks,
  LoginHookError,
  rotateLoginHookSecret,
  sendTestCall,
  serializeInvocation,
  serializeLoginHook,
  setLoginHook,
} from '../services/loginHookService.js';
import { AuthenticatedRequest } from '../types/types.js';

function actorUserId(req: Request) {
  return (req as AuthenticatedRequest).user?.id ?? null;
}

function trigger(req: Request) {
  return req.params.trigger as LoginHookTrigger;
}

/** Recorded without its query string, where a hook service may have put a token. */
function auditedUrl(url: string) {
  const parsed = new URL(url);
  return `${parsed.origin}${parsed.pathname}`;
}

function sendError(res: Response, error: unknown) {
  if (error instanceof LoginHookError) {
    return res.status(error.status).json({ error: error.message });
  }

  throw error;
}

export async function listHooks(_req: Request, res: Response) {
  const hooks = await listLoginHooks();
  return res.json({ hooks: hooks.map(serializeLoginHook) });
}

export async function getHook(req: Request, res: Response) {
  try {
    return res.json({ hook: serializeLoginHook(await getLoginHook(trigger(req))) });
  } catch (error) {
    return sendError(res, error);
  }
}

export async function setHook(req: Request, res: Response) {
  try {
    const { hook, secret, created } = await setLoginHook(trigger(req), req.body, actorUserId(req));

    await AuthEventService.log({
      actorUserId: actorUserId(req),
      type: 'admin_login_hook_set',
      req,
      metadata: {
        trigger: hook.trigger,
        created,
        url: auditedUrl(hook.url),
        timeoutMs: hook.timeoutMs,
        failureMode: hook.failureMode,
        enabled: hook.enabled,
      },
    });

    return res
      .status(created ? 201 : 200)
      .json({ hook: serializeLoginHook(hook), ...(secret ? { secret } : {}) });
  } catch (error) {
    return sendError(res, error);
  }
}

export async function deleteHook(req: Request, res: Response) {
  try {
    const hook = await deleteLoginHook(trigger(req));

    await AuthEventService.log({
      actorUserId: actorUserId(req),
      type: 'admin_login_hook_deleted',
      req,
      metadata: { trigger: hook.trigger, url: auditedUrl(hook.url) },
    });

    return res.json({ message: 'Login hook deleted' });
  } catch (error) {
    return sendError(res, error);
  }
}

export async function rotateHookSecret(req: Request, res: Response) {
  try {
    const { hook, secret, previousSecretExpiresAt } = await rotateLoginHookSecret(trigger(req));

    await AuthEventService.log({
      actorUserId: actorUserId(req),
      type: 'admin_login_hook_secret_rotated',
      req,
      metadata: { trigger: hook.trigger },
    });

    return res.json({ secret, previousSecretExpiresAt: previousSecretExpiresAt.toISOString() });
  } catch (error) {
    return sendError(res, error);
  }
}

export async function testHook(req: Request, res: Response) {
  try {
    return res.json(await sendTestCall(trigger(req)));
  } catch (error) {
    return sendError(res, error);
  }
}

export async function listHookInvocations(req: Request, res: Response) {
  const invocations = await listInvocations(
    trigger(req),
    req.query as unknown as LoginHookInvocationQuery,
  );
  return res.json({ invocations: invocations.map(serializeInvocation) });
}
