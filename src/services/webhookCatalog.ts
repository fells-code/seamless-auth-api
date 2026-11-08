/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import type {
  CredentialKind,
  SessionRevokedReason,
  WebhookEvent,
  WebhookEventType,
} from '@seamless-auth/types';

/** The audit row fields a webhook is built from. */
export type DispatchableAuthEvent = {
  seq: string;
  type: string;
  user_id: string | null;
  session_id: string | null;
  metadata: Record<string, unknown> | null;
  created_at: Date;
};

export type WebhookSubject = { email: string | null; phone: string | null };

export type WebhookEventBody = Extract<WebhookEvent, { type: WebhookEventType }>;

type Built = { type: WebhookEventType; data: WebhookEventBody['data'] };

const SESSION_REVOKED: Readonly<Record<string, SessionRevokedReason>> = {
  logout_success: 'logout',
  admin_session_revoked: 'admin',
  session_evicted: 'evicted',
  oidc_session_revoked: 'provider',
};

const ORGANIZATION_MEMBER: Readonly<Record<string, WebhookEventType>> = {
  organization_member_added: 'organization.member_added',
  organization_member_updated: 'organization.member_updated',
  organization_member_removed: 'organization.member_removed',
};

function text(value: unknown): string | null {
  return typeof value === 'string' && value ? value : null;
}

function strings(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === 'string')
    : [];
}

/**
 * Which audit types become which webhook (ADR 0005, D3). The audit types are internal and many;
 * the webhook catalog is a public contract, so this table is the whole mapping and
 * `tests/unit/services/webhookCatalog.spec.ts` pins it. An audit type added later reaches no
 * receiver until it is added here.
 */
export const WEBHOOK_SOURCE_TYPES: Readonly<Record<string, WebhookEventType>> = {
  user_created: 'user.created',
  user_deleted: 'user.deleted',
  session_created: 'user.signed_in',
  account_recovery_completed: 'user.recovered',
  logout_success: 'session.revoked',
  admin_session_revoked: 'session.revoked',
  session_evicted: 'session.revoked',
  oidc_session_revoked: 'session.revoked',
  registration_success: 'credential.added',
  totp_enrollment_success: 'credential.added',
  recovery_codes_generated: 'credential.added',
  credentials_deleted: 'credential.removed',
  totp_disabled: 'credential.removed',
  organization_member_added: 'organization.member_added',
  organization_member_updated: 'organization.member_updated',
  organization_member_removed: 'organization.member_removed',
};

function credentialKind(event: DispatchableAuthEvent): CredentialKind | null {
  switch (event.type) {
    case 'totp_enrollment_success':
    case 'totp_disabled':
      return 'totp';
    case 'recovery_codes_generated':
      return 'recovery_codes';
    default:
      // `registration_success` is also written when an account is registered, and
      // `credentials_deleted` when an account is deleted. Only the rows that name a passkey are
      // about a credential.
      return event.metadata?.credential === 'passkey' ? 'passkey' : null;
  }
}

/**
 * The session a revocation is about. For a sign-out and a provider revocation that is the session
 * the request came from. An administrator's revocation and an eviction name it in metadata,
 * because the request's own session is the administrator's or the new one. Signing out everywhere
 * names no single session.
 */
function revokedSessionId(event: DispatchableAuthEvent): string | null {
  switch (event.type) {
    case 'logout_success':
      return event.metadata?.scope === 'current_session' ? event.session_id : null;
    case 'oidc_session_revoked':
      return event.session_id;
    default:
      return text(event.metadata?.sessionId);
  }
}

/**
 * The webhook an audit row becomes, or null when it becomes none. `subject` is read from the
 * user at dispatch, for `user.created`, which carries the address the account was made with.
 */
export function webhookEventFor(
  event: DispatchableAuthEvent,
  subject: WebhookSubject | null,
): Built | null {
  const type = WEBHOOK_SOURCE_TYPES[event.type];
  if (!type) return null;

  const userId = event.user_id;

  switch (type) {
    case 'user.created':
      return userId
        ? {
            type,
            data: { userId, email: subject?.email ?? null, phone: subject?.phone ?? null },
          }
        : null;
    case 'user.deleted':
    case 'user.recovered':
      return userId ? { type, data: { userId } } : null;
    case 'user.signed_in':
      return userId
        ? {
            type,
            data: {
              userId,
              sessionId: event.session_id,
              method: text(event.metadata?.method),
              organizationId: text(event.metadata?.organizationId),
            },
          }
        : null;
    case 'session.revoked':
      return {
        type,
        data: {
          userId,
          sessionId: revokedSessionId(event),
          reason: SESSION_REVOKED[event.type],
        },
      };
    case 'credential.added':
    case 'credential.removed': {
      const kind = credentialKind(event);
      return userId && kind
        ? { type, data: { userId, kind, credentialId: text(event.metadata?.credentialId) } }
        : null;
    }
    default: {
      const organizationId = text(event.metadata?.organizationId);
      if (!userId || !organizationId || !ORGANIZATION_MEMBER[event.type]) return null;
      return {
        type,
        data: {
          organizationId,
          userId,
          roles: event.type === 'organization_member_removed' ? [] : strings(event.metadata?.roles),
        },
      };
    }
  }
}
