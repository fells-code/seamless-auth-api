import { describe, expect, it } from 'vitest';

import {
  authEventOutcome,
  AUTH_EVENT_CATEGORIES,
  categorizeAuthEvent,
} from '../../../src/lib/authEventCategories.js';
import { AUTH_EVENT_TYPES } from '../../../src/schemas/authEvent.types.js';

describe('categorizeAuthEvent', () => {
  it('keeps WebAuthn and OAuth logins out of the generic login bucket', () => {
    expect(categorizeAuthEvent('webauthn_login_success')).toBe('webauthn');
    expect(categorizeAuthEvent('webauthn_registration_failed')).toBe('webauthn');
    expect(categorizeAuthEvent('oauth_login_started')).toBe('oauth');
    expect(categorizeAuthEvent('login_success')).toBe('login');
    expect(categorizeAuthEvent('logout_success')).toBe('login');
  });

  it('groups every OTP variant together and keeps TOTP separate', () => {
    expect(categorizeAuthEvent('otp_success')).toBe('otp');
    expect(categorizeAuthEvent('mfa_otp_failed')).toBe('otp');
    expect(categorizeAuthEvent('recovery_otp_success')).toBe('otp');
    expect(categorizeAuthEvent('verify_otp_failed')).toBe('otp');
    expect(categorizeAuthEvent('totp_enrollment_success')).toBe('totp');
  });

  it('routes suspicious events to the security bucket regardless of surface', () => {
    expect(categorizeAuthEvent('login_suspicious')).toBe('suspicious');
    expect(categorizeAuthEvent('webauthn_login_suspicious')).toBe('suspicious');
    expect(categorizeAuthEvent('request_suspicious')).toBe('suspicious');
  });

  it('falls back to other for an unrecognized type', () => {
    expect(categorizeAuthEvent('something_new')).toBe('other');
  });

  it('assigns every known event type to a declared category', () => {
    for (const type of AUTH_EVENT_TYPES) {
      expect(AUTH_EVENT_CATEGORIES).toContain(categorizeAuthEvent(type));
    }
  });

  it('leaves no known event type in the other bucket', () => {
    const uncategorized = AUTH_EVENT_TYPES.filter((type) => categorizeAuthEvent(type) === 'other');

    expect(uncategorized).toEqual([]);
  });
});

describe('authEventOutcome', () => {
  it('derives the outcome from the type suffix', () => {
    expect(authEventOutcome('login_success')).toBe('success');
    expect(authEventOutcome('magic_link_poll_completed_successfully')).toBe('success');
    expect(authEventOutcome('login_failed')).toBe('failed');
    expect(authEventOutcome('system_config_error')).toBe('failed');
    expect(authEventOutcome('login_suspicious')).toBe('suspicious');
    expect(authEventOutcome('magic_link_requested')).toBe('other');
  });
});
