/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { Request } from 'express';

import { AuthEvent } from '../models/authEvents.js';
import type { AuthEventType } from '../schemas/authEvent.types.js';
import type { AuthenticatedRequest } from '../types/types.js';
import getLogger from '../utils/logger.js';
import { redactMetadata } from '../utils/redaction.js';

const logger = getLogger('authEventService');

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
  type: LoggableAuthEventType;
  req: Request;
  metadata?: Record<string, unknown> | null;
}

interface AuthEventContextOptions {
  userId?: string | null;
  actorUserId?: string | null;
  sessionId?: string | null;
  type: LoggableAuthEventType;
  ipAddress?: string | null;
  userAgent?: string | null;
  metadata?: Record<string, unknown> | null;
}

export class AuthEventService {
  static async logContext({
    userId = null,
    actorUserId = null,
    sessionId = null,
    type,
    ipAddress = 'unknown',
    userAgent = 'unknown',
    metadata = null,
  }: AuthEventContextOptions) {
    try {
      await AuthEvent.create({
        user_id: userId,
        actor_user_id: actorUserId,
        session_id: sessionId,
        type: normalizeAuthEventType(type),
        ip_address: ipAddress || 'unknown',
        user_agent: userAgent || 'unknown',
        metadata: redactMetadata(metadata),
      });
    } catch (err) {
      logger.error(`Failed to write AuthEvent: ${err}`);
    }
  }

  static async log({
    userId = null,
    actorUserId = null,
    sessionId,
    type,
    req,
    metadata = null,
  }: AuthEventOptions) {
    return this.logContext({
      userId,
      actorUserId,
      sessionId: sessionId ?? (req as AuthenticatedRequest).sessionId ?? null,
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
