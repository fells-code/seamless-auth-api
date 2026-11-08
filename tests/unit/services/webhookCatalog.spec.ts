import { WEBHOOK_EVENT_TYPES, WebhookEventSchema } from '@seamless-auth/types';
import { describe, expect, it } from 'vitest';

import { AUTH_EVENT_TYPES } from '../../../src/schemas/authEvent.types.js';
import {
  type DispatchableAuthEvent,
  WEBHOOK_SOURCE_TYPES,
  webhookEventFor,
} from '../../../src/services/webhookCatalog.js';

function row(type: string, overrides: Partial<DispatchableAuthEvent> = {}): DispatchableAuthEvent {
  return {
    seq: '10',
    type,
    user_id: 'user-1',
    session_id: 'session-1',
    metadata: null,
    created_at: new Date('2026-11-07T12:00:00.000Z'),
    ...overrides,
  };
}

function parses(built: ReturnType<typeof webhookEventFor>) {
  expect(built).not.toBeNull();
  return WebhookEventSchema.parse({
    id: 'delivery-1',
    version: 1,
    timestamp: '2026-11-07T12:00:00.000Z',
    ...built,
  });
}

describe('webhook catalog', () => {
  // The catalog is a public contract. Adding an audit type must not change what receivers get
  // unless this table changes with it.
  it('pins which audit types become which webhook', () => {
    expect(WEBHOOK_SOURCE_TYPES).toEqual({
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
    });
  });

  it('maps only audit types that exist, and reaches every catalog type', () => {
    for (const source of Object.keys(WEBHOOK_SOURCE_TYPES)) {
      expect(AUTH_EVENT_TYPES).toContain(source);
    }
    expect([...new Set(Object.values(WEBHOOK_SOURCE_TYPES))].sort()).toEqual(
      [...WEBHOOK_EVENT_TYPES].sort(),
    );
  });

  it('ignores audit types outside the catalog', () => {
    expect(webhookEventFor(row('login_success'), null)).toBeNull();
    expect(webhookEventFor(row('login_failed'), null)).toBeNull();
  });

  it('builds user.created with the address the account was made with', () => {
    const event = parses(
      webhookEventFor(row('user_created'), { email: 'a@example.com', phone: null }),
    );
    expect(event.data).toEqual({ userId: 'user-1', email: 'a@example.com', phone: null });
  });

  it('builds user.created without an address when the user is already gone', () => {
    expect(parses(webhookEventFor(row('user_created'), null)).data).toEqual({
      userId: 'user-1',
      email: null,
      phone: null,
    });
  });

  it.each(['user_created', 'user_deleted', 'account_recovery_completed', 'session_created'])(
    'drops %s without a user',
    (type) => {
      expect(webhookEventFor(row(type, { user_id: null }), null)).toBeNull();
    },
  );

  it('builds user.deleted and user.recovered', () => {
    expect(parses(webhookEventFor(row('user_deleted'), null)).type).toBe('user.deleted');
    expect(parses(webhookEventFor(row('account_recovery_completed'), null)).type).toBe(
      'user.recovered',
    );
  });

  it('builds user.signed_in from session_created, with no network detail', () => {
    const event = parses(
      webhookEventFor(
        row('session_created', { metadata: { method: 'passkey', organizationId: 'org-1' } }),
        null,
      ),
    );

    expect(event.data).toEqual({
      userId: 'user-1',
      sessionId: 'session-1',
      method: 'passkey',
      organizationId: 'org-1',
    });
  });

  it.each([
    ['logout_success', { scope: 'current_session' }, 'session-1', 'logout'],
    ['logout_success', { scope: 'all_sessions' }, null, 'logout'],
    // The request's own session is the administrator's, never the one revoked.
    ['admin_session_revoked', { sessionId: 'target' }, 'target', 'admin'],
    ['admin_session_revoked', { targetUser: 'user-1' }, null, 'admin'],
    ['session_evicted', { sessionId: 'old' }, 'old', 'evicted'],
    ['oidc_session_revoked', { reason: 'logout' }, 'session-1', 'provider'],
  ])('builds session.revoked from %s %j', (type, metadata, sessionId, reason) => {
    const event = parses(webhookEventFor(row(type, { metadata }), null));
    expect(event.data).toEqual({ userId: 'user-1', sessionId, reason });
  });

  it.each([
    [
      'registration_success',
      { credential: 'passkey', credentialId: 'cred-1' },
      'passkey',
      'cred-1',
    ],
    ['totp_enrollment_success', null, 'totp', null],
    ['recovery_codes_generated', null, 'recovery_codes', null],
  ])('builds credential.added from %s', (type, metadata, kind, credentialId) => {
    const event = parses(webhookEventFor(row(type, { metadata }), null));
    expect(event).toMatchObject({ type: 'credential.added', data: { kind, credentialId } });
  });

  it.each([
    ['credentials_deleted', { credential: 'passkey', credentialId: 'cred-1' }, 'passkey'],
    ['totp_disabled', null, 'totp'],
  ])('builds credential.removed from %s', (type, metadata, kind) => {
    expect(parses(webhookEventFor(row(type, { metadata }), null))).toMatchObject({
      type: 'credential.removed',
      data: { kind },
    });
  });

  // Account registration and account deletion write the same audit types without naming a passkey.
  it('drops registration_success and credentials_deleted that are not about a passkey', () => {
    expect(webhookEventFor(row('registration_success', { metadata: {} }), null)).toBeNull();
    expect(
      webhookEventFor(
        row('credentials_deleted', { metadata: { reason: 'User deleted account' } }),
        null,
      ),
    ).toBeNull();
    expect(webhookEventFor(row('totp_disabled', { user_id: null }), null)).toBeNull();
  });

  it.each([
    ['organization_member_added', ['member'], ['member']],
    ['organization_member_updated', ['admin', 7], ['admin']],
    ['organization_member_removed', ['admin'], []],
  ])('builds the organization event from %s', (type, roles, expected) => {
    const event = parses(
      webhookEventFor(row(type, { metadata: { organizationId: 'org-1', roles } }), null),
    );
    expect(event.data).toEqual({ organizationId: 'org-1', userId: 'user-1', roles: expected });
  });

  it('builds roles as empty when the row carries none', () => {
    expect(
      parses(
        webhookEventFor(
          row('organization_member_added', { metadata: { organizationId: 'o' } }),
          null,
        ),
      ).data,
    ).toMatchObject({ roles: [] });
  });

  it('drops an organization event without an organization or user', () => {
    expect(webhookEventFor(row('organization_member_added', { metadata: {} }), null)).toBeNull();
    expect(
      webhookEventFor(
        row('organization_member_added', { user_id: null, metadata: { organizationId: 'o' } }),
        null,
      ),
    ).toBeNull();
  });
});
