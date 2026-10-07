import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  reviewAccountMetadata,
  reviewAccountSettings,
  reviewCodeFor,
} from '../../../src/lib/reviewAccounts.js';

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

  describe('reviewAccountMetadata', () => {
    it('flags an address that is issued the fixed code', () => {
      process.env.REVIEW_ACCOUNT_EMAILS = 'review@example.com';
      process.env.REVIEW_ACCOUNT_CODE = 'REVUEW';

      expect(reviewAccountMetadata('Review@Example.com')).toEqual({ reviewAccount: true });
    });

    it('adds nothing for any other address, or when the code is unusable', () => {
      process.env.REVIEW_ACCOUNT_EMAILS = 'review@example.com';
      process.env.REVIEW_ACCOUNT_CODE = 'REVUEW';

      expect(reviewAccountMetadata('someone@example.com')).toEqual({});
      expect(reviewAccountMetadata(undefined)).toEqual({});

      process.env.REVIEW_ACCOUNT_CODE = '123456';
      expect(reviewAccountMetadata('review@example.com')).toEqual({});
    });
  });

  describe('reviewAccountSettings', () => {
    it('is off with nothing configured', () => {
      expect(reviewAccountSettings()).toEqual({
        enabled: false,
        emails: [],
        codeConfigured: false,
      });
    });

    it('is on with addresses and a usable code, listing each address once, normalized', () => {
      process.env.REVIEW_ACCOUNT_EMAILS =
        ' Review@Example.com,second@example.com,,review@example.com';
      process.env.REVIEW_ACCOUNT_CODE = 'revuew';

      expect(reviewAccountSettings()).toEqual({
        enabled: true,
        emails: ['review@example.com', 'second@example.com'],
        codeConfigured: true,
      });
    });

    it('is off when the code is unusable, while still listing the addresses', () => {
      process.env.REVIEW_ACCOUNT_EMAILS = 'review@example.com';
      process.env.REVIEW_ACCOUNT_CODE = 'ABC';

      expect(reviewAccountSettings()).toEqual({
        enabled: false,
        emails: ['review@example.com'],
        codeConfigured: false,
      });
    });

    it('is off when a code is set but no address is', () => {
      process.env.REVIEW_ACCOUNT_CODE = 'REVUEW';

      expect(reviewAccountSettings()).toEqual({
        enabled: false,
        emails: [],
        codeConfigured: true,
      });
    });
  });
});
