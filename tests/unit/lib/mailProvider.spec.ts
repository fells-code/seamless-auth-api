import { describe, expect, it } from 'vitest';

import { MAIL_PROVIDERS, mailProviderFor } from '../../../src/lib/mailProvider.js';

describe('mailProviderFor', () => {
  it.each([
    ['gmail', 'someone@gmail.com'],
    ['gmail', 'someone@googlemail.com'],
    ['outlook', 'someone@outlook.com'],
    ['outlook', 'someone@hotmail.com'],
    ['outlook', 'someone@live.com'],
    ['yahoo', 'someone@yahoo.com'],
    ['yahoo', 'someone@ymail.com'],
    ['icloud', 'someone@icloud.com'],
    ['icloud', 'someone@me.com'],
    ['icloud', 'someone@mac.com'],
    ['proton', 'someone@proton.me'],
    ['proton', 'someone@protonmail.com'],
    ['proton', 'someone@pm.me'],
    ['aol', 'someone@aol.com'],
    ['fastmail', 'someone@fastmail.com'],
    ['fastmail', 'someone@fastmail.fm'],
    ['gmx', 'someone@gmx.de'],
    ['zoho', 'someone@zoho.com'],
    ['yandex', 'someone@yandex.ru'],
  ])('maps to %s: %s', (expected, email) => {
    expect(mailProviderFor(email)).toBe(expected);
  });

  it('matches regional variants on the leftmost label', () => {
    expect(mailProviderFor('someone@yahoo.co.uk')).toBe('yahoo');
    expect(mailProviderFor('someone@hotmail.fr')).toBe('outlook');
    expect(mailProviderFor('someone@outlook.de')).toBe('outlook');
  });

  it('is case and whitespace insensitive', () => {
    expect(mailProviderFor('Someone@GMAIL.COM ')).toBe('gmail');
  });

  // The domain is never returned. A family or small business domain is an address.
  it('folds every other domain into other rather than naming it', () => {
    expect(mailProviderFor('owner@corbett-family.com')).toBe('other');
    expect(mailProviderFor('someone@example.org')).toBe('other');
    // A short label that would be a provider is only a provider on its own domain.
    expect(mailProviderFor('someone@me.example.com')).toBe('other');
  });

  // `constructor` is a valid DNS label. On an object literal it finds Object.prototype
  // and the audit row that carried it would fail validation and be dropped.
  it('does not let a domain label reach the prototype', () => {
    expect(mailProviderFor('someone@constructor.io')).toBe('other');
    expect(mailProviderFor('someone@constructor.com')).toBe('other');
    expect(mailProviderFor('someone@tostring.dev')).toBe('other');
    expect(mailProviderFor('someone@hasownproperty.example')).toBe('other');
  });

  it('answers null for a missing or malformed address', () => {
    expect(mailProviderFor(null)).toBeNull();
    expect(mailProviderFor(undefined)).toBeNull();
    expect(mailProviderFor('')).toBeNull();
    expect(mailProviderFor('no-at-sign')).toBeNull();
    expect(mailProviderFor('@gmail.com')).toBeNull();
    expect(mailProviderFor('someone@')).toBeNull();
  });

  it('only ever answers with a listed provider', () => {
    for (const email of ['a@gmail.com', 'a@example.com', 'a@pm.me']) {
      expect(MAIL_PROVIDERS).toContain(mailProviderFor(email));
    }
  });
});
