/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

// src/schemas/authEvent.types.ts
import { z } from 'zod';

export const AUTH_EVENT_TYPES = [
  'auth_action_incremented',
  'admin_device_replacement_recovery',
  'admin_session_revoked',
  'credentials_deleted',
  'informational',
  'internal_user_updated_by_owner',
  'login_challenge',
  'login_failed',
  'login_success',
  'login_suspicious',
  'logout_failed',
  'logout_success',
  'logout_suspicious',
  'magic_link_poll_completed_successfully',
  'magic_link_failed',
  'magic_link_requested',
  'magic_link_success',
  'mfa_otp_failed',
  'mfa_otp_success',
  'notification_sent',
  'oauth_login_failed',
  'oauth_login_started',
  'oauth_login_success',
  'otp_success',
  'otp_suspicious',
  'refresh_token_failed',
  'refresh_token_success',
  'refresh_token_suspicious',
  'registration_failed',
  'registration_success',
  'registration_suspicious',
  'request_suspicious',
  'service_token_failed',
  'service_token_rotated',
  'service_token_success',
  'session_evicted',
  'step_up_challenge',
  'step_up_failed',
  'step_up_success',
  'step_up_suspicious',
  'system_config_error',
  'system_config_read',
  'system_config_updated',
  'totp_disabled',
  'totp_enrollment_started',
  'totp_enrollment_success',
  'totp_failed',
  'totp_success',
  'totp_suspicious',
  'user_created',
  'user_data_suspicious',
  'user_deleted',
  'verify_otp_failed',
  'verify_otp_success',
  'verify_otp_suspicious',
  'webauthn_login_failed',
  'webauthn_login_success',
  'webauthn_registration_challenge',
  'webauthn_registration_failed',
  'webauthn_registration_suspicious',
] as const;

export const AuthEventTypeEnum = z.enum(AUTH_EVENT_TYPES);

export type AuthEventType = z.infer<typeof AuthEventTypeEnum>;

/**
 * Types grouped by outcome, derived rather than hand-listed.
 *
 * Consumers used to keep their own copies of these groupings, which drifted: the
 * anomaly detector searched for `otp_failed`, `bearer_token_failed`, and three other
 * names nothing emitted, so those failures were invisible, while `verify_otp_failed`
 * and `magic_link_failed` were emitted and never searched for. Deriving the groups
 * means adding an event type puts it in the right bucket automatically.
 */
export const FAILURE_EVENT_TYPES = AUTH_EVENT_TYPES.filter((type) =>
  type.endsWith('_failed'),
) as readonly AuthEventType[];

export const SUSPICIOUS_EVENT_TYPES = AUTH_EVENT_TYPES.filter((type) =>
  type.endsWith('_suspicious'),
) as readonly AuthEventType[];

/** Types belonging to a flow, matched on the event-type prefix. */
export function authEventTypesFor(...prefixes: string[]): AuthEventType[] {
  return AUTH_EVENT_TYPES.filter((type) =>
    prefixes.some((prefix) => type === prefix || type.startsWith(`${prefix}_`)),
  );
}
