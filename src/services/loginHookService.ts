/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { randomUUID } from 'node:crypto';

import {
  type CalloutFailure,
  type CalloutTestResponse,
  claimValueDepth,
  CUSTOM_CLAIM_MAX_DEPTH,
  CUSTOM_CLAIM_NAME_PATTERN,
  CUSTOM_CLAIMS_BUDGET_BYTES,
  customClaimsByteLength,
  isReservedClaimName,
  LoginHookCallSchema,
  type LoginHookFailureMode,
  type LoginHookInvocationQuery,
  type LoginHookTrigger,
  PostLoginHookResultSchema,
  PreTokenHookResultSchema,
  type SetLoginHookRequest,
  WEBHOOK_SECRET_ROTATION_OVERLAP_SECONDS,
} from '@seamless-auth/types';
import type { Request } from 'express';
import { Op } from 'sequelize';

import { productionSecretMissing } from '../config/authSecrets.js';
import {
  calloutSigningSecrets,
  encryptCalloutSecret,
  generateCalloutSecret,
  signedCalloutHeaders,
} from '../lib/calloutSigning.js';
import { CalloutError, calloutRequest, calloutUrlProblem } from '../lib/calloutTransport.js';
import { LoginHookInvocation } from '../models/loginHookInvocations.js';
import { LoginHook } from '../models/loginHooks.js';
import getLogger from '../utils/logger.js';
import { AuthEventService } from './authEventService.js';
import { findMembership } from './organizationService.js';

const logger = getLogger('loginHooks');

export class LoginHookError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = 'LoginHookError';
  }
}

const MAX_RESPONSE_BYTES = 64 * 1024;
const INVOCATION_RETENTION_DAYS = 30;
const PRUNE_INTERVAL_MS = 60 * 60 * 1000;

export type HookClaims = Record<string, unknown>;

export type LoginHookContext = {
  user: { id: string; email: string | null; phone: string | null; roles: string[] };
  method: string | null;
  organizationId: string | null;
  /** The membership's roles, when the caller has just read them. Otherwise they are read here. */
  organizationRoles?: string[];
  req: Request;
};

export type LoginHookVerdict =
  | { outcome: 'skipped' }
  | { outcome: 'allowed'; claims: HookClaims | null }
  | { outcome: 'denied'; userMessage: string | null }
  | { outcome: 'failed_open' }
  | { outcome: 'failed_closed' };

export type LoginHookRefusal =
  | { status: 403; body: { error: 'login_denied'; message?: string } }
  | { status: 503; body: { error: 'login_hook_unavailable' } };

/**
 * What a sign-in answers when a hook stops it. A deny shows only the hook's `userMessage`, never
 * its `reason`, which may hold internal detail.
 */
export function loginHookRefusal(verdict: LoginHookVerdict): LoginHookRefusal | null {
  if (verdict.outcome === 'denied') {
    return {
      status: 403,
      body: {
        error: 'login_denied',
        ...(verdict.userMessage ? { message: verdict.userMessage } : {}),
      },
    };
  }
  if (verdict.outcome === 'failed_closed') {
    return { status: 503, body: { error: 'login_hook_unavailable' } };
  }
  return null;
}

/** The claims a `pre_token` verdict puts on the session, or null when it adds none. */
export function verdictClaims(verdict: LoginHookVerdict): HookClaims | null {
  return verdict.outcome === 'allowed' ? verdict.claims : null;
}

function now() {
  return new Date();
}

export function serializeLoginHook(hook: LoginHook) {
  const rotating =
    hook.previousSecretExpiresAt && hook.previousSecretExpiresAt > now()
      ? hook.previousSecretExpiresAt.toISOString()
      : null;

  return {
    trigger: hook.trigger,
    url: hook.url,
    timeoutMs: hook.timeoutMs,
    failureMode: hook.failureMode,
    enabled: hook.enabled,
    previousSecretExpiresAt: rotating,
    createdAt: hook.createdAt.toISOString(),
    updatedAt: hook.updatedAt.toISOString(),
  };
}

export function serializeInvocation(invocation: LoginHookInvocation) {
  return {
    id: invocation.id,
    trigger: invocation.trigger,
    userId: invocation.userId ?? null,
    outcome: invocation.outcome,
    failure: invocation.failure ?? null,
    statusCode: invocation.statusCode ?? null,
    durationMs: invocation.durationMs,
    createdAt: invocation.createdAt.toISOString(),
  };
}

function assertUrl(url: string) {
  const problem = calloutUrlProblem(url);
  if (problem) throw new LoginHookError(400, `url ${problem}`);
}

function assertSecretKey() {
  if (productionSecretMissing('CALLOUT_SECRET_ENCRYPTION_KEY')) {
    throw new LoginHookError(
      409,
      'CALLOUT_SECRET_ENCRYPTION_KEY must be set before a login hook can be created',
    );
  }
}

function secretColumns(secret: string) {
  const { ciphertext, iv, tag } = encryptCalloutSecret(secret);
  return { secretCiphertext: ciphertext, secretIv: iv, secretTag: tag };
}

export async function listLoginHooks() {
  return LoginHook.findAll({ order: [['trigger', 'ASC']] });
}

export async function getLoginHook(trigger: LoginHookTrigger) {
  const hook = await LoginHook.findByPk(trigger);
  if (!hook) throw new LoginHookError(404, 'Login hook not found');
  return hook;
}

/** Creates the trigger's hook, or replaces its settings. The secret survives a replace. */
export async function setLoginHook(
  trigger: LoginHookTrigger,
  input: SetLoginHookRequest,
  actorUserId: string | null,
) {
  assertUrl(input.url);
  const settings = {
    url: input.url,
    timeoutMs: input.timeoutMs,
    failureMode: input.failureMode,
    enabled: input.enabled,
  };

  const existing = await LoginHook.findByPk(trigger);
  if (existing) {
    await existing.update(settings);
    return { hook: existing, secret: undefined, created: false };
  }

  assertSecretKey();
  const secret = generateCalloutSecret();
  const hook = await LoginHook.create({
    trigger,
    ...settings,
    createdBy: actorUserId,
    ...secretColumns(secret),
  });

  return { hook, secret, created: true };
}

export async function deleteLoginHook(trigger: LoginHookTrigger) {
  const hook = await getLoginHook(trigger);
  await hook.destroy();
  return hook;
}

/** Like a webhook's: the old secret signs beside the new one for a day, and only two ever sign. */
export async function rotateLoginHookSecret(trigger: LoginHookTrigger) {
  assertSecretKey();
  const hook = await getLoginHook(trigger);
  const secret = generateCalloutSecret();
  const previousSecretExpiresAt = new Date(
    now().getTime() + WEBHOOK_SECRET_ROTATION_OVERLAP_SECONDS * 1000,
  );

  await hook.update({
    previousSecretCiphertext: hook.secretCiphertext,
    previousSecretIv: hook.secretIv,
    previousSecretTag: hook.secretTag,
    previousSecretExpiresAt,
    ...secretColumns(secret),
  });

  return { hook, secret, previousSecretExpiresAt };
}

export async function listInvocations(
  trigger: LoginHookTrigger,
  { limit, outcome }: LoginHookInvocationQuery,
) {
  return LoginHookInvocation.findAll({
    where: { trigger, ...(outcome ? { outcome } : {}) },
    order: [['createdAt', 'DESC']],
    limit,
  });
}

export async function pruneLoginHookInvocations(at: Date = now()) {
  return LoginHookInvocation.destroy({
    where: {
      createdAt: {
        [Op.lt]: new Date(at.getTime() - INVOCATION_RETENTION_DAYS * 24 * 60 * 60 * 1000),
      },
    },
  });
}

export function startLoginHookMaintenance() {
  const timer = setInterval(() => {
    pruneLoginHookInvocations().catch((error: unknown) => {
      logger.error(`Pruning login hook invocations failed: ${(error as Error).message}`);
    });
  }, PRUNE_INTERVAL_MS);
  timer.unref();
  return timer;
}

class HookFailure extends Error {
  constructor(
    readonly failure: CalloutFailure,
    readonly statusCode: number | null,
    readonly detail: string,
  ) {
    super(detail);
    this.name = 'HookFailure';
  }
}

type Answer = {
  decision: 'allow' | 'deny';
  reason?: string;
  userMessage?: string;
  claims: HookClaims | null;
  stripped: string[];
  statusCode: number;
};

/**
 * Reserved names are dropped (and the caller audits which), since a hook asserting `sub` or
 * `email` is the one thing it must never do. Anything else that does not fit the custom claim
 * rules fails the hook rather than being trimmed into something the hook did not send.
 */
export function screenHookClaims(claims: Record<string, unknown>) {
  const kept: HookClaims = {};
  const stripped: string[] = [];

  for (const [name, value] of Object.entries(claims)) {
    if (isReservedClaimName(name)) {
      stripped.push(name);
      continue;
    }
    if (!CUSTOM_CLAIM_NAME_PATTERN.test(name)) {
      throw new HookFailure('invalid_response', null, 'claim name is not allowed');
    }
    if (claimValueDepth(value) > CUSTOM_CLAIM_MAX_DEPTH) {
      throw new HookFailure('invalid_response', null, 'claim value nests too deeply');
    }
    kept[name] = value;
  }

  if (customClaimsByteLength(kept) > CUSTOM_CLAIMS_BUDGET_BYTES) {
    throw new HookFailure('too_large', null, 'claims exceed the custom claims budget');
  }

  return { kept, stripped };
}

function readAnswer(trigger: LoginHookTrigger, status: number, body: Buffer): Answer {
  // A redirect is a failure too: following it would carry the signed body to an unchecked host.
  if (status < 200 || status >= 300) {
    throw new HookFailure('http_status', status, `hook answered ${status}`);
  }

  let json: unknown;
  try {
    json = JSON.parse(body.toString('utf8'));
  } catch {
    throw new HookFailure('invalid_response', status, 'hook answered with a body that is not JSON');
  }

  if (trigger === 'post_login') {
    const parsed = PostLoginHookResultSchema.safeParse(json);
    if (!parsed.success) {
      throw new HookFailure('invalid_response', status, 'hook answer did not parse');
    }
    return { ...parsed.data, claims: null, stripped: [], statusCode: status };
  }

  const parsed = PreTokenHookResultSchema.safeParse(json);
  if (!parsed.success) {
    throw new HookFailure('invalid_response', status, 'hook answer did not parse');
  }
  if (parsed.data.decision === 'deny') {
    return { ...parsed.data, claims: null, stripped: [], statusCode: status };
  }

  try {
    const { kept, stripped } = screenHookClaims(parsed.data.claims ?? {});
    return { ...parsed.data, claims: kept, stripped, statusCode: status };
  } catch (error) {
    if (error instanceof HookFailure) throw new HookFailure(error.failure, status, error.detail);
    throw error;
  }
}

async function callHook(hook: LoginHook, id: string, payload: string): Promise<Answer> {
  let response;
  try {
    response = await calloutRequest(hook.url, {
      method: 'POST',
      headers: signedCalloutHeaders(id, payload, calloutSigningSecrets(hook)),
      body: payload,
      timeoutMs: hook.timeoutMs,
      maxResponseBytes: MAX_RESPONSE_BYTES,
    });
  } catch (error) {
    if (error instanceof CalloutError) throw new HookFailure(error.failure, null, error.message);
    // A secret that no longer decrypts, or anything else unexpected, is still this hook failing.
    throw new HookFailure('connection_failed', null, 'hook call failed');
  }

  return readAnswer(hook.trigger, response.status, response.body);
}

async function organizationFor(context: Omit<LoginHookContext, 'req'>) {
  if (!context.organizationId) return null;
  const roles =
    context.organizationRoles ??
    (await findMembership(context.user.id, context.organizationId))?.roles ??
    [];
  return { id: context.organizationId, roles: Array.isArray(roles) ? roles : [] };
}

type CallRequest = { ipAddress: string | null; userAgent: string | null };

function requestOf(req: Request): CallRequest {
  return { ipAddress: req.ip ?? null, userAgent: req.get('user-agent') ?? null };
}

async function callBody(
  id: string,
  trigger: LoginHookTrigger,
  context: Omit<LoginHookContext, 'req'>,
  request: CallRequest,
) {
  // Parsed rather than trusted, so nothing beyond the published shape can reach a hook, and
  // in particular no token, code or secret.
  return JSON.stringify(
    LoginHookCallSchema.parse({
      id,
      trigger,
      timestamp: now(),
      user: {
        id: context.user.id,
        email: context.user.email ?? null,
        phone: context.user.phone ?? null,
        roles: context.user.roles ?? [],
      },
      method: context.method,
      organization: await organizationFor(context),
      client: null,
      request,
    }),
  );
}

async function record(
  id: string,
  hook: LoginHook,
  context: LoginHookContext,
  outcome: 'allowed' | 'denied' | 'failed_open' | 'failed_closed',
  durationMs: number,
  statusCode: number | null,
  failure: CalloutFailure | null,
) {
  await LoginHookInvocation.create({
    id,
    trigger: hook.trigger,
    userId: context.user.id,
    outcome,
    failure,
    statusCode,
    durationMs,
  });
}

function failedOutcome(mode: LoginHookFailureMode) {
  return mode === 'open' ? 'failed_open' : 'failed_closed';
}

/**
 * One attempt. Every invocation is recorded and audited. A hook that is missing or turned off
 * is skipped, which lets the sign-in through as if it did not exist.
 */
export async function runLoginHook(
  trigger: LoginHookTrigger,
  context: LoginHookContext,
): Promise<LoginHookVerdict> {
  const hook = await LoginHook.findByPk(trigger);
  if (!hook || !hook.enabled) return { outcome: 'skipped' };

  const id = randomUUID();
  const started = Date.now();
  const base = { invocationId: id, trigger };

  try {
    const answer = await callHook(
      hook,
      id,
      await callBody(id, trigger, context, requestOf(context.req)),
    );
    const durationMs = Date.now() - started;

    if (answer.decision === 'deny') {
      await record(id, hook, context, 'denied', durationMs, answer.statusCode, null);
      await AuthEventService.log({
        userId: context.user.id,
        type: 'login_hook_denied',
        req: context.req,
        metadata: { ...base, durationMs, ...(answer.reason ? { reason: answer.reason } : {}) },
      });
      return { outcome: 'denied', userMessage: answer.userMessage ?? null };
    }

    await record(id, hook, context, 'allowed', durationMs, answer.statusCode, null);
    if (answer.stripped.length > 0) {
      await AuthEventService.log({
        userId: context.user.id,
        type: 'login_hook_claims_stripped',
        req: context.req,
        metadata: { ...base, names: answer.stripped },
      });
    }
    await AuthEventService.log({
      userId: context.user.id,
      type: 'login_hook_success',
      req: context.req,
      metadata: {
        ...base,
        durationMs,
        ...(answer.claims ? { claimNames: Object.keys(answer.claims) } : {}),
      },
    });
    return { outcome: 'allowed', claims: answer.claims };
  } catch (error) {
    if (!(error instanceof HookFailure)) throw error;

    const durationMs = Date.now() - started;
    const outcome = failedOutcome(hook.failureMode);
    await record(id, hook, context, outcome, durationMs, error.statusCode, error.failure);
    await AuthEventService.log({
      userId: context.user.id,
      type: 'login_hook_failed',
      req: context.req,
      metadata: {
        ...base,
        durationMs,
        failure: error.failure,
        statusCode: error.statusCode,
        failureMode: hook.failureMode,
        detail: error.detail,
      },
    });
    return { outcome };
  }
}

const TEST_USER_ID = '00000000-0000-4000-8000-000000000000';

/**
 * One call with a placeholder user and no request details, so a hook can be checked without
 * signing anyone in. Not recorded as an invocation, since the sign-in it describes never happened.
 */
export async function sendTestCall(trigger: LoginHookTrigger): Promise<CalloutTestResponse> {
  const hook = await getLoginHook(trigger);
  const id = randomUUID();
  const started = Date.now();
  const payload = await callBody(
    id,
    trigger,
    {
      user: { id: TEST_USER_ID, email: null, phone: null, roles: [] },
      method: null,
      organizationId: null,
    },
    { ipAddress: null, userAgent: null },
  );

  try {
    const answer = await callHook(hook, id, payload);
    return {
      ok: true,
      failure: null,
      statusCode: answer.statusCode,
      durationMs: Date.now() - started,
    };
  } catch (error) {
    if (!(error instanceof HookFailure)) throw error;
    return {
      ok: false,
      failure: error.failure,
      statusCode: error.statusCode,
      durationMs: Date.now() - started,
    };
  }
}
