/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

export const AUTH_EVENT_CATEGORIES = [
  'suspicious',
  'login',
  'registration',
  'webauthn',
  'oauth',
  'magicLink',
  'otp',
  'totp',
  'stepUp',
  'token',
  'system',
  'other',
] as const;

export type AuthEventCategory = (typeof AUTH_EVENT_CATEGORIES)[number];

export const AUTH_EVENT_OUTCOMES = ['success', 'failed', 'suspicious', 'other'] as const;

export type AuthEventOutcome = (typeof AUTH_EVENT_OUTCOMES)[number];

const PREFIX_CATEGORIES: ReadonlyArray<[string, AuthEventCategory]> = [
  ['webauthn_', 'webauthn'],
  ['oauth_', 'oauth'],
  ['magic_link', 'magicLink'],
  ['totp_', 'totp'],
  ['step_up_', 'stepUp'],
  ['mfa_otp_', 'otp'],
  ['recovery_otp_', 'otp'],
  ['verify_otp_', 'otp'],
  ['otp_', 'otp'],
  ['registration_', 'registration'],
  ['login_', 'login'],
  ['logout_', 'login'],
  ['refresh_token_', 'token'],
  ['bearer_token_', 'token'],
  ['service_token_', 'token'],
  ['jwks_', 'token'],
  ['system_config_', 'system'],
  ['admin_', 'system'],
  ['user_data_', 'system'],
];

const EXACT_CATEGORIES: Readonly<Record<string, AuthEventCategory>> = {
  auth_action_incremented: 'system',
  credentials_deleted: 'webauthn',
  informational: 'system',
  internal_user_updated_by_owner: 'system',
  notification_sent: 'system',
  user_created: 'registration',
  user_deleted: 'system',
};

// `suspicious` is checked first so security signals stay in one bucket rather than
// being split across the surface they came from. Categories are mutually exclusive,
// so the counts in a summary sum to the total number of events.
export function categorizeAuthEvent(type: string): AuthEventCategory {
  if (type.endsWith('_suspicious')) return 'suspicious';

  const exact = EXACT_CATEGORIES[type];
  if (exact) return exact;

  for (const [prefix, category] of PREFIX_CATEGORIES) {
    if (type.startsWith(prefix)) return category;
  }

  return 'other';
}

export function authEventOutcome(type: string): AuthEventOutcome {
  if (type.endsWith('_suspicious')) return 'suspicious';
  if (type.endsWith('_failed') || type.endsWith('_error')) return 'failed';
  if (type.endsWith('_success') || type.endsWith('_successfully')) return 'success';

  return 'other';
}
