/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

/**
 * The mail providers deliverability is reported by.
 *
 * A fixed list of consumer providers plus `other`, never the domain itself. A domain is
 * an address for anyone on a family or small business domain, and the rows this feeds
 * are meant to be published. The cost is that a custom domain hosted on Google
 * Workspace or Microsoft 365 lands in `other`, since telling those apart takes an MX
 * lookup on the send path.
 */
export const MAIL_PROVIDERS = [
  'gmail',
  'outlook',
  'yahoo',
  'icloud',
  'proton',
  'aol',
  'fastmail',
  'gmx',
  'zoho',
  'yandex',
  'other',
] as const;

export type MailProvider = (typeof MAIL_PROVIDERS)[number];

// Maps rather than object literals: the key comes from an address anyone can register,
// and `constructor` is a valid DNS label that would otherwise find Object.prototype.
//
// Matched on the leftmost label of the domain, so `yahoo.co.uk` and `hotmail.fr` land
// with their provider without listing every country code.
const PROVIDER_BY_LABEL = new Map<string, MailProvider>([
  ['gmail', 'gmail'],
  ['googlemail', 'gmail'],
  ['outlook', 'outlook'],
  ['hotmail', 'outlook'],
  ['live', 'outlook'],
  ['msn', 'outlook'],
  ['yahoo', 'yahoo'],
  ['ymail', 'yahoo'],
  ['rocketmail', 'yahoo'],
  ['icloud', 'icloud'],
  ['proton', 'proton'],
  ['protonmail', 'proton'],
  ['aol', 'aol'],
  ['fastmail', 'fastmail'],
  ['gmx', 'gmx'],
  ['zoho', 'zoho'],
  ['yandex', 'yandex'],
]);

// Labels too short or too common to match on their own.
const PROVIDER_BY_DOMAIN = new Map<string, MailProvider>([
  ['me.com', 'icloud'],
  ['mac.com', 'icloud'],
  ['pm.me', 'proton'],
  ['fastmail.fm', 'fastmail'],
]);

export function mailProviderFor(email: string | null | undefined): MailProvider | null {
  const at = email?.lastIndexOf('@') ?? -1;

  if (!email || at < 1 || at === email.length - 1) return null;

  const domain = email
    .slice(at + 1)
    .trim()
    .toLowerCase();
  const label = domain.split('.')[0];

  return PROVIDER_BY_DOMAIN.get(domain) ?? PROVIDER_BY_LABEL.get(label) ?? 'other';
}
