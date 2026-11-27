import { beforeEach, describe, expect, it, vi } from 'vitest';

import {
  decoyCredentialIdFor,
  decoyPrincipalForSubject,
  decoySubjectFor,
  isRegistrationDecoySubject,
  registrationDecoySubjectFor,
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
    vi.stubEnv('SEAMLESS_SERVICE_TOKEN', 'a-service-token-that-is-never-used-for-this');

    // A decoy subject derived from a guessable key is not a decoy, so booting without
    // one has to fail loudly rather than quietly producing forgeable subjects.
    expect(() => decoySubjectFor('nobody@example.com', 'email')).toThrow(
      'DECOY_SUBJECT_SECRET must be set in production.',
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

  it('does not always claim a passkey', () => {
    // `loginMethods` is filtered by what an account can do, so a decoy that always
    // claimed the full set would make any narrower set proof that a real account
    // exists. Both shapes have to occur for a narrow list to be ambiguous.
    const shapes = new Set<boolean>();
    const phones = new Set<boolean>();

    for (let i = 0; i < 200; i += 1) {
      const principal = decoyPrincipalForSubject(decoySubjectFor(`user${i}@example.com`, 'email'));

      shapes.add(principal.hasPasskey);
      phones.add(principal.phone !== null);
    }

    expect(shapes).toEqual(new Set([true, false]));
    expect(phones).toEqual(new Set([true, false]));
  });

  it('keeps one identifier on the same shape', () => {
    const subject = decoySubjectFor('nobody@example.com', 'email');

    expect(decoyPrincipalForSubject(subject).hasPasskey).toBe(
      decoyPrincipalForSubject(subject).hasPasskey,
    );
  });

  it('reads as a usable account', () => {
    const principal = decoyPrincipalForSubject(decoySubjectFor('nobody@example.com', 'email'));

    expect(principal).toEqual(
      expect.objectContaining({ verified: true, revoked: false, roles: [] }),
    );
    expect(principal.email).toBeTruthy();
  });
});

describe('fabricated secrets', () => {
  it('produces a credential id shaped like a real one', () => {
    const subject = decoySubjectFor('nobody@example.com', 'email');

    expect(decoyCredentialIdFor(subject)).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });
});

describe('registrationDecoySubjectFor', () => {
  it('is a stable v4 UUID per address, folded for case', () => {
    const subject = registrationDecoySubjectFor('Owner@Example.com');

    expect(subject).toMatch(UUID_V4);
    expect(registrationDecoySubjectFor('owner@example.com')).toBe(subject);
    expect(registrationDecoySubjectFor('other@example.com')).not.toBe(subject);
  });

  it('never matches the subject /login derives for the same address', () => {
    expect(registrationDecoySubjectFor('owner@example.com')).not.toBe(
      decoySubjectFor('owner@example.com', 'email'),
    );
  });

  it('is recognised from the subject alone, and nothing else is', () => {
    expect(isRegistrationDecoySubject(registrationDecoySubjectFor('owner@example.com'))).toBe(true);
    expect(isRegistrationDecoySubject(decoySubjectFor('owner@example.com', 'email'))).toBe(false);
    expect(isRegistrationDecoySubject('6f1c2a9e-3b7d-4c11-9a2e-5d8f0b4c7e21')).toBe(false);
    expect(isRegistrationDecoySubject('not-a-uuid')).toBe(false);
  });

  it('depends on the key, so a tag cannot be forged without it', () => {
    const subject = registrationDecoySubjectFor('owner@example.com');

    vi.stubEnv('DECOY_SUBJECT_SECRET', 'a-different-secret-of-sufficient-length-for-tests');

    expect(isRegistrationDecoySubject(subject)).toBe(false);
  });

  it('reads as a sign-up nobody has claimed', () => {
    for (let i = 0; i < 32; i += 1) {
      const principal = decoyPrincipalForSubject(registrationDecoySubjectFor(`probe${i}@x.com`));

      expect(principal).toEqual(
        expect.objectContaining({
          verified: false,
          emailVerified: false,
          phoneVerified: false,
          hasPasskey: false,
        }),
      );
    }
  });
});
