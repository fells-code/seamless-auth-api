/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

/**
 * App store reviewers sign in to a demo account, and they cannot read the
 * inbox a passwordless code goes to. An address listed in
 * `REVIEW_ACCOUNT_EMAILS` is issued `REVIEW_ACCOUNT_CODE` instead of a random
 * email code, so the code can go in the review notes. Everything after that is
 * the ordinary flow: the code is stored hashed, expires, is rate limited, and
 * is still mailed. Both unset, nothing changes.
 *
 * A fixed code does not rotate, so a review account should hold nothing worth
 * taking, and the variables should be cleared once review is over.
 */

const REVIEW_CODE_PATTERN = /^[A-Z]{6}$/;

/** Audit metadata key marking an event as being about a review address. */
export const REVIEW_ACCOUNT_METADATA_KEY = 'reviewAccount';

function reviewEmails(): Set<string> {
  return new Set(
    (process.env.REVIEW_ACCOUNT_EMAILS ?? '')
      .split(',')
      .map((entry) => entry.trim().toLowerCase())
      .filter(Boolean),
  );
}

function configuredCode(): string | null {
  const code = (process.env.REVIEW_ACCOUNT_CODE ?? '').trim().toUpperCase();
  return REVIEW_CODE_PATTERN.test(code) ? code : null;
}

/**
 * The configured code for a review address, or null. A code that is not six
 * letters is never used, since the clients accept nothing else.
 */
export function reviewCodeFor(email: string | null | undefined): string | null {
  if (!email || !reviewEmails().has(email.trim().toLowerCase())) {
    return null;
  }
  return configuredCode();
}

/**
 * Spread into the metadata of an email OTP event. Only an address that is issued
 * the fixed code is flagged, so a listed address with an unusable code, which gets
 * a random code like anyone else, is not.
 */
export function reviewAccountMetadata(email: string | null | undefined): {
  [REVIEW_ACCOUNT_METADATA_KEY]?: true;
} {
  return reviewCodeFor(email) ? { [REVIEW_ACCOUNT_METADATA_KEY]: true } : {};
}

export function reviewAccountSettings() {
  const emails = [...reviewEmails()];
  const codeConfigured = configuredCode() !== null;

  return { enabled: emails.length > 0 && codeConfigured, emails, codeConfigured };
}
