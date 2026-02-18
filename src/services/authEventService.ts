/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import { Request } from 'express';

import { AuthEvent } from '../models/authEvents';
import getLogger from '../utils/logger';

const logger = getLogger('authEventService');

type AuthEventType =
  | 'login_success'
  | 'login_failed'
  | 'login_suspicious'
  | 'registration_success'
  | 'registration_failed'
  | 'registration_suspicious'
  | 'webauthn_registration_success'
  | 'webauthn_registration_failed'
  | 'webauthn_registration_suspicious'
  | 'webauthn_login_success'
  | 'webauthn_login_failed'
  | 'webauthn_login_suspicious'
  | 'logout_success'
  | 'logout_failed'
  | 'logout_suspicious'
  | 'jwks_success'
  | 'jwks_failed'
  | 'jwks_suspicious'
  | 'otp_success'
  | 'otp_failed'
  | 'otp_suspicious'
  | 'verify_otp_success'
  | 'verify_otp_failed'
  | 'verify_otp_suspicious'
  | 'mfa_otp_success'
  | 'mfa_otp_failed'
  | 'mfa_otp_suspicious'
  | 'recovery_otp_success'
  | 'recovery_otp_failed'
  | 'recovery_otp_suspicious'
  | 'user_created'
  | 'user_data_success'
  | 'user_data_failed'
  | 'user_data_suspicious'
  | 'service_token_success'
  | 'service_token_failed'
  | 'service_token_suspicious'
  | 'refresh_token_success'
  | 'refresh_token_failed'
  | 'refresh_token_suspicious'
  | 'service_token_rotated'
  | 'bearer_token_success'
  | 'bearer_token_failed'
  | 'bearer_token_suspicious'
  | 'cookie_token_success'
  | 'cookie_token_failed'
  | 'cookie_token_suspicious'
  | 'auth_action_incremented'
  | 'system_config_updated'
  | 'system_config_error'
  | 'system_config_read'
  | 'notication_sent'
  | 'magic_link_requested'
  | 'magic_link_success'
  | 'informational';

export interface AuthEventOptions {
  userId?: string | null;
  type: AuthEventType;
  req: Request;
  metadata?: Record<string, unknown> | null;
}

export class AuthEventService {
  static async log({ userId = null, type, req, metadata = null }: AuthEventOptions) {
    try {
      await AuthEvent.create({
        user_id: userId,
        type,
        ip_address: req.ip || 'unknown',
        user_agent: req.headers['user-agent'] || 'unknown',
        metadata,
      });
    } catch (err) {
      logger.error('Failed to write AuthEvent:', err);
    }
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
    return this.log({ userId: by, type: 'notication_sent', req, metadata });
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
}
