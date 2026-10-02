import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { reviewCodeFor } from '../../../src/lib/reviewAccounts.js';

describe('reviewCodeFor', () => {
  const original = {
    emails: process.env.REVIEW_ACCOUNT_EMAILS,
    code: process.env.REVIEW_ACCOUNT_CODE,
  };

  function restore(name: string, value: string | undefined) {
    if (value === undefined) {
      delete process.env[name];
    } else {
      process.env[name] = value;
    }
  }

  beforeEach(() => {
    delete process.env.REVIEW_ACCOUNT_EMAILS;
    delete process.env.REVIEW_ACCOUNT_CODE;
  });

  afterEach(() => {
    restore('REVIEW_ACCOUNT_EMAILS', original.emails);
    restore('REVIEW_ACCOUNT_CODE', original.code);
  });

  it('is null when nothing is configured', () => {
    expect(reviewCodeFor('review@example.com')).toBeNull();
  });

  it('gives a listed address the configured code, matched case-insensitively', () => {
    process.env.REVIEW_ACCOUNT_EMAILS = 'other@example.com, Review@Example.com';
    process.env.REVIEW_ACCOUNT_CODE = ' revuew ';

    expect(reviewCodeFor('  review@example.com ')).toBe('REVUEW');
    expect(reviewCodeFor('other@example.com')).toBe('REVUEW');
  });

  it('is null for an address that is not listed', () => {
    process.env.REVIEW_ACCOUNT_EMAILS = 'review@example.com';
    process.env.REVIEW_ACCOUNT_CODE = 'REVUEW';

    expect(reviewCodeFor('someone@example.com')).toBeNull();
    expect(reviewCodeFor(null)).toBeNull();
  });

  it('never uses a code the clients would not accept', () => {
    process.env.REVIEW_ACCOUNT_EMAILS = 'review@example.com';

    for (const code of ['', 'ABC', 'ABCDEFG', '123456', 'ABC 12']) {
      process.env.REVIEW_ACCOUNT_CODE = code;
      expect(reviewCodeFor('review@example.com')).toBeNull();
    }
  });
});
