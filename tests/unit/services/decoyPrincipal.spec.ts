import { beforeEach, describe, expect, it, vi } from 'vitest';

import {
  decoyCredentialIdFor,
  decoyOtpFor,
  decoyPrincipalForSubject,
  decoySubjectFor,
} from '../../../src/services/decoyPrincipal.js';

const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

beforeEach(() => {
  vi.unstubAllEnvs();
});

describe('decoySubjectFor', () => {
  it('is stable for the same identifier', () => {
    expect(decoySubjectFor('nobody@example.com', 'email')).toBe(
      decoySubjectFor('nobody@example.com', 'email'),
    );
  });

  it('folds case the way the account lookup does', () => {
    // /login looks an email up lowercased, so two spellings of one address must not
    // produce two subjects when they would have produced one row.
    expect(decoySubjectFor('NOBODY@example.com', 'email')).toBe(
      decoySubjectFor('nobody@example.com', 'email'),
    );
  });

  it('differs between identifiers', () => {
    expect(decoySubjectFor('a@example.com', 'email')).not.toBe(
      decoySubjectFor('b@example.com', 'email'),
    );
  });

  it('differs between identifier types', () => {
    expect(decoySubjectFor('+15555550100', 'phone')).not.toBe(
      decoySubjectFor('+15555550100', 'email'),
    );
  });

  it('is shaped like the UUIDV4 the users table generates', () => {
    // A subject that failed a version or variant check would announce itself as
    // synthetic to anyone who looked at it.
    expect(decoySubjectFor('nobody@example.com', 'email')).toMatch(UUID_V4);
  });

  it('changes with the secret', () => {
    const before = decoySubjectFor('nobody@example.com', 'email');

    vi.stubEnv('DECOY_SUBJECT_SECRET', 'a-different-secret');

    expect(decoySubjectFor('nobody@example.com', 'email')).not.toBe(before);
  });

  it('refuses to invent a secret in production', () => {
    vi.stubEnv('NODE_ENV', 'production');
    vi.stubEnv('DECOY_SUBJECT_SECRET', '');
    vi.stubEnv('API_SERVICE_TOKEN', '');

    // A decoy subject derived from a guessable key is not a decoy, so booting without
    // one has to fail loudly rather than quietly producing forgeable subjects.
    expect(() => decoySubjectFor('nobody@example.com', 'email')).toThrow(
      /DECOY_SUBJECT_SECRET or API_SERVICE_TOKEN/,
    );
  });
});

describe('decoy principal', () => {
  it('carries an email and phone so identity rate limiting still buckets per identifier', () => {
    const principal = decoyPrincipalForSubject(decoySubjectFor('nobody@example.com', 'email'));

    // Left empty, the OTP and magic link limiters fall back to an IP bucket, so every
    // unknown identifier probed from one address would share a counter while every real
    // one got its own. That difference is an oracle built out of 429s.
    expect(principal.email).toMatch(/^[0-9a-f]{24}@example\.invalid$/);
    expect(principal.phone).toMatch(/^\+1555\d{7}$/);
  });

  it('derives the same details from the same subject', () => {
    const subject = decoySubjectFor('nobody@example.com', 'email');

    expect(decoyPrincipalForSubject(subject)).toEqual(decoyPrincipalForSubject(subject));
  });

  it('reads as a usable account', () => {
    const principal = decoyPrincipalForSubject(decoySubjectFor('nobody@example.com', 'email'));

    expect(principal).toEqual(
      expect.objectContaining({ verified: true, revoked: false, roles: [] }),
    );
  });
});

describe('fabricated secrets', () => {
  it('produces a six digit OTP', () => {
    const subject = decoySubjectFor('nobody@example.com', 'email');

    expect(decoyOtpFor(subject)).toMatch(/^\d{6}$/);
    expect(decoyOtpFor(subject)).toBe(decoyOtpFor(subject));
  });

  it('produces a credential id shaped like a real one', () => {
    const subject = decoySubjectFor('nobody@example.com', 'email');

    expect(decoyCredentialIdFor(subject)).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });
});
