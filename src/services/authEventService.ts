/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { Request } from 'express';

import { classifyDeviceClass } from '../lib/deviceClass.js';
import { mailProviderFor } from '../lib/mailProvider.js';
import { isOwnerEmail } from '../lib/ownerAdmin.js';
import { AuthEvent } from '../models/authEvents.js';
import type { AuthEventType } from '../schemas/authEvent.types.js';
import type { AuthenticatedRequest } from '../types/types.js';
import { redactMetadata } from '../utils/redaction.js';
import { recordAuditWriteFailure } from './auditHealth.js';
import { recordAuthFailure } from './authFailureCounter.js';

type DeprecatedAuthEventType = 'notication_sent' | 'registration_suspicous' | 'request_suspicous';

type LoggableAuthEventType = AuthEventType | DeprecatedAuthEventType;

const AUTH_EVENT_TYPE_ALIASES: Record<DeprecatedAuthEventType, AuthEventType> = {
  notication_sent: 'notification_sent',
  registration_suspicous: 'registration_suspicious',
  request_suspicous: 'request_suspicious',
};

function normalizeAuthEventType(type: LoggableAuthEventType): AuthEventType {
  return AUTH_EVENT_TYPE_ALIASES[type as DeprecatedAuthEventType] ?? type;
}

export interface AuthEventOptions {
  userId?: string | null;
  /**
   * Who performed the action, when that is not the subject of it. Set this on
   * anything an administrator does to another account; without it the event
   * reads as though the user did it to themselves.
   */
  actorUserId?: string | null;
  /**
   * The session the action was taken from. Defaults to the session on the
   * request, which the bearer middleware sets for any access-token call, so
   * authenticated events correlate without every call site passing it.
   */
  sessionId?: string | null;
  /**
   * The sign-in or registration attempt the event belongs to. Defaults to the
   * attempt on the request, which the bearer middleware sets from the ephemeral
   * token's `jti`, so every step taken on that token correlates without call sites
   * passing it. `/login` and `/registration/register` start an attempt, so they
   * pass the id they are about to mint the token with.
   */
  attemptId?: string | null;
  /**
   * The address of the user the event is about, for the mail provider and owner
   * dimensions. Never stored. Defaults to the request principal's address when the
   * principal is the subject, which covers every step taken on a token. Pass it
   * where the subject is known before a token exists (`/login`,
   * `/registration/register`) or without one (OAuth).
   */
  subjectEmail?: string | null;
  type: LoggableAuthEventType;
  req: Request;
  metadata?: Record<string, unknown> | null;
}

interface AuthEventContextOptions {
  userId?: string | null;
  actorUserId?: string | null;
  sessionId?: string | null;
  attemptId?: string | null;
  subjectEmail?: string | null;
  type: LoggableAuthEventType;
  ipAddress?: string | null;
  userAgent?: string | null;
  metadata?: Record<string, unknown> | null;
}

function deploymentId() {
  return process.env.APP_ID?.trim() || null;
}

/**
 * The principal's address, when the principal is the subject of the event.
 *
 * An administrator acting on someone else's account is on the request with the
 * target in `userId`, and a decoy principal's address belongs to nobody, so neither
 * says anything about the subject.
 */
function principalEmailFor(req: Request, userId: string | null) {
  const { user, decoy } = req as AuthenticatedRequest;

  if (!user || decoy || !userId || user.id !== userId) return null;

  return user.email ?? null;
}

export class AuthEventService {
  static async logContext({
    userId = null,
    actorUserId = null,
    sessionId = null,
    attemptId = null,
    subjectEmail = null,
    type,
    ipAddress = 'unknown',
    userAgent = 'unknown',
    metadata = null,
  }: AuthEventContextOptions) {
    const normalizedType = normalizeAuthEventType(type);

    // Counted before the audit write and in its own statement, so a trail that
    // cannot be written no longer takes the lockout control down with it. This
    // used to be derived from auth_events, which meant the control and its
    // telemetry shared one failure mode and both failed open.
    await recordAuthFailure({ userId, type: normalizedType });

    try {
      await AuthEvent.create({
        user_id: userId,
        actor_user_id: actorUserId,
        session_id: sessionId,
        type: normalizedType,
        ip_address: ipAddress || 'unknown',
        user_agent: userAgent || 'unknown',
        deployment_id: deploymentId(),
        device_class: classifyDeviceClass(userAgent),
        mail_provider: mailProviderFor(subjectEmail),
        owner: subjectEmail ? isOwnerEmail(subjectEmail) : null,
        attempt_id: attemptId,
        metadata: redactMetadata(metadata),
      });
    } catch (err) {
      // Still swallowed: 137 call sites await this, many from inside error
      // handlers, and throwing here would turn a bookkeeping failure into a
      // failed request. The failure is no longer silent, though. It is reported
      // through /health/status so a monitor can act on it.
      recordAuditWriteFailure(err);
    }
  }

  static async log({
    userId = null,
    actorUserId = null,
    sessionId,
    attemptId,
    subjectEmail,
    type,
    req,
    metadata = null,
  }: AuthEventOptions) {
    return this.logContext({
      userId,
      actorUserId,
      sessionId: sessionId ?? (req as AuthenticatedRequest).sessionId ?? null,
      attemptId: attemptId ?? (req as AuthenticatedRequest).attemptId ?? null,
      subjectEmail: subjectEmail ?? principalEmailFor(req, userId),
      type,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      metadata,
    });
  }

  static loginSuccess(userId: string, req: Request) {
    return this.log({ userId, type: 'login_success', req });
  }

  static loginFailed(reason: string, userId: string | null, req: Request) {
    return this.log({
      userId,
      type: 'login_failed',
      req,
      metadata: { reason },
    });
  }

  static tokenRotated(userId: string, req: Request, metadata?: Record<string, string>) {
    return this.log({
      userId,
      type: 'service_token_rotated',
      req,
      metadata,
    });
  }

  static authActionTake(by: string, req: Request, metadata?: Record<string, string>) {
    return this.log({ userId: by, type: 'auth_action_incremented', req, metadata });
  }

  static notificationSent(by: string, req: Request, metadata?: Record<string, string>) {
    return this.log({ userId: by, type: 'notification_sent', req, metadata });
  }

  static serviceTokenUsed(clientId: string, req: Request) {
    return this.log({
      type: 'service_token_success',
      metadata: { clientId },
      req,
    });
  }

  static serviceTokenInvalid(req: Request) {
    return this.log({
      type: 'service_token_failed',
      metadata: null,
      req,
    });
  }

  static refreshTokenFailed(req: Request, metadata?: Record<string, unknown> | null) {
    return this.log({
      type: 'refresh_token_failed',
      metadata: metadata ?? null,
      req,
    });
  }

  static requestSuspicious(req: Request, metadata?: Record<string, unknown> | null) {
    return this.log({
      type: 'request_suspicious',
      metadata: metadata ?? null,
      req,
    });
  }

  static requestSuspiciousContext(
    context: { ipAddress?: string | null; userAgent?: string | null },
    metadata?: Record<string, unknown> | null,
  ) {
    return this.logContext({
      type: 'request_suspicious',
      ipAddress: context.ipAddress,
      userAgent: context.userAgent,
      metadata: metadata ?? null,
    });
  }
}
