import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
  AUTH_EVENT_TYPES,
  authEventTypesFor,
  FAILURE_EVENT_TYPES,
  SUSPICIOUS_EVENT_TYPES,
} from '../../../src/schemas/authEvent.types.js';

const srcDir = join(dirname(fileURLToPath(import.meta.url)), '../../../src');

// The declaration itself and the generated client both list every type verbatim, so
// including them would make the emit check pass vacuously.
const EXCLUDED = new Set(['authEvent.types.ts', 'generated']);

function collectSources(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    if (EXCLUDED.has(entry.name)) return [];

    const path = join(dir, entry.name);

    if (entry.isDirectory()) return collectSources(path);

    return entry.name.endsWith('.ts') ? [readFileSync(path, 'utf8')] : [];
  });
}

function sourceOutsideTheDeclaration() {
  return collectSources(srcDir).join('\n');
}

describe('auth event type coverage', () => {
  it('emits every declared event type from somewhere in src', () => {
    const blob = sourceOutsideTheDeclaration();
    const emitted = new Set(Array.from(blob.matchAll(/type:\s*'([a-z0-9_]+)'/g), (m) => m[1]));

    // A type nobody emits is dead weight: consumers filter and alert on names that
    // never arrive, which is how the anomaly detector ended up searching for five
    // events that were never written.
    const neverEmitted = AUTH_EVENT_TYPES.filter((type) => !emitted.has(type));

    expect(neverEmitted).toEqual([]);
  });

  it('derives the failure and suspicious groups from the declared types', () => {
    expect(FAILURE_EVENT_TYPES.every((type) => type.endsWith('_failed'))).toBe(true);
    expect(SUSPICIOUS_EVENT_TYPES.every((type) => type.endsWith('_suspicious'))).toBe(true);

    expect(FAILURE_EVENT_TYPES).toContain('verify_otp_failed');
    expect(FAILURE_EVENT_TYPES).toContain('magic_link_failed');
  });

  it('groups a flow by prefix without matching unrelated types', () => {
    const otp = authEventTypesFor('otp', 'verify_otp', 'mfa_otp');

    expect(otp).toContain('otp_success');
    expect(otp).toContain('verify_otp_failed');
    expect(otp).toContain('mfa_otp_success');
    // `totp_*` is a different flow and must not be swept in by a substring match.
    expect(otp.some((type) => type.startsWith('totp'))).toBe(false);
  });
});
