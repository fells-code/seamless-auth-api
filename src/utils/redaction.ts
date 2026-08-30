/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

export const REDACTED = '[REDACTED]';

const MAX_DEPTH = 8;
const MAX_ARRAY_ITEMS = 50;

const SENSITIVE_KEY_PATTERN =
  /(^|_|\b)(access[_-]?token|assertion|authorization|bearer|bootstrap[_-]?token|challenge|client[_-]?secret|code|cookie|ciphertext|email|email[_-]?address|email[_-]?verification[_-]?token|ephemeral[_-]?token|id[_-]?token|identifier|invite[_-]?url|iv|magic[_-]?link[_-]?url|magic[_-]?token|nonce|otp|password|phone|phone[_-]?number|phone[_-]?verification[_-]?token|prf|prf[_-]?(output|result|results|salt)|private[_-]?key|recovery[_-]?code|refresh[_-]?token|salt|secret|state|tag|token|totp[_-]?secret|verification[_-]?token)$/i;

const TOKEN_TEXT_PATTERNS: Array<[RegExp, string]> = [
  [/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, REDACTED],
  [/\+[1-9]\d{6,14}\b/g, REDACTED],
  [/\b(Bearer\s+)[A-Za-z0-9._~+/=-]+/gi, `$1${REDACTED}`],
  [/(\/magic-link\/verify\/)[^/?#\s]+/gi, `$1${REDACTED}`],
  [
    /([?&](?:token|bootstrapToken|verificationToken|otp|state|code|salt)=)[^&#\s]+/gi,
    `$1${REDACTED}`,
  ],
  [
    /\b((?:token|bootstrapToken|verificationToken|identifier|email(?:\s+address)?|phone(?:\s+number)?|state|code|secret|salt)\s*[:=]\s*)[^,&\s}]+/gi,
    `$1${REDACTED}`,
  ],
  [/\b(client_secret=)[^&\s]+/gi, `$1${REDACTED}`],
];

export function isSensitiveKey(key: string) {
  return SENSITIVE_KEY_PATTERN.test(key);
}

export function redactSensitiveText(value: string) {
  return TOKEN_TEXT_PATTERNS.reduce(
    (current, [pattern, replacement]) => current.replace(pattern, replacement),
    value,
  );
}

/**
 * A log entry is one line, so a newline in an interpolated value lets a caller forge a
 * second entry. Request paths, provider ids and the like reach log messages through
 * template strings across the codebase, so this runs centrally in the logger format
 * rather than at each call site, where one missed interpolation reopens the hole.
 */
export function escapeLogControlCharacters(value: string) {
  // eslint-disable-next-line no-control-regex
  return value.replace(/[\u0000-\u001f\u007f]/g, (character) => {
    if (character === '\n') return '\\n';
    if (character === '\r') return '\\r';
    if (character === '\t') return '\\t';
    return `\\x${character.charCodeAt(0).toString(16).padStart(2, '0')}`;
  });
}

export function redactSensitiveValue(value: unknown, depth = 0): unknown {
  if (value === null || value === undefined) {
    return value;
  }

  if (typeof value === 'string') {
    return redactSensitiveText(value);
  }

  if (typeof value !== 'object') {
    return value;
  }

  if (depth >= MAX_DEPTH) {
    return '[REDACTED_DEPTH_LIMIT]';
  }

  if (value instanceof Date) {
    return value.toISOString();
  }

  if (Array.isArray(value)) {
    return value.slice(0, MAX_ARRAY_ITEMS).map((item) => redactSensitiveValue(item, depth + 1));
  }

  // Null prototype because the keys come from untrusted audit metadata. On a normal
  // object a `__proto__` key hits the setter instead of creating an own property, so
  // it vanishes from the output unredacted and swaps the prototype for whatever the
  // caller sent.
  const redacted = Object.create(null) as Record<string, unknown>;

  for (const [key, nestedValue] of Object.entries(value as Record<string, unknown>)) {
    redacted[key] = isSensitiveKey(key) ? REDACTED : redactSensitiveValue(nestedValue, depth + 1);
  }

  return redacted;
}

export function redactMetadata<T extends Record<string, unknown> | null | undefined>(
  metadata: T,
): T {
  if (metadata === null || metadata === undefined) {
    return metadata;
  }

  return redactSensitiveValue(metadata) as T;
}
