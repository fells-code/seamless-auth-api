import { isoCBOR } from '@simplewebauthn/server/helpers';
import { describe, expect, it, vi } from 'vitest';

import { classifyAttestation } from '../../../src/lib/attestationType';

// Real CBOR, so the classification is exercised against the encoding the library
// actually hands back rather than a stand-in for it.
vi.unmock('@simplewebauthn/server');

function attestationObject(fmt: string, attStmt: Map<string, unknown>) {
  return isoCBOR.encode(
    new Map<string, unknown>([
      ['fmt', fmt],
      ['attStmt', attStmt],
      ['authData', new Uint8Array([1, 2, 3])],
    ]) as never,
  );
}

const CERT = new Uint8Array([0x30, 0x82, 0x01]);

describe('classifyAttestation', () => {
  it('reports no attestation when none was requested', () => {
    expect(classifyAttestation('none', attestationObject('none', new Map()))).toBe('none');
  });

  it('reports no attestation when the format is missing entirely', () => {
    expect(classifyAttestation(undefined, undefined)).toBe('none');
  });

  it('reports self attestation for packed without a certificate chain', () => {
    const attStmt = new Map<string, unknown>([
      ['alg', -7],
      ['sig', new Uint8Array([9])],
    ]);

    expect(classifyAttestation('packed', attestationObject('packed', attStmt))).toBe('self');
  });

  it('reports basic attestation for packed with a certificate chain', () => {
    const attStmt = new Map<string, unknown>([
      ['alg', -7],
      ['sig', new Uint8Array([9])],
      ['x5c', [CERT]],
    ]);

    expect(classifyAttestation('packed', attestationObject('packed', attStmt))).toBe('basic');
  });

  // Every other format refuses to verify without a chain, so reaching this point
  // at all means one was presented. SafetyNet carries it in the JWS header rather
  // than x5c, which is why the format is trusted here instead of the statement.
  it.each(['fido-u2f', 'tpm', 'android-key', 'android-safetynet', 'apple'])(
    'reports basic attestation for %s',
    (fmt) => {
      expect(classifyAttestation(fmt, attestationObject(fmt, new Map()))).toBe('basic');
    },
  );

  it('reports self attestation for packed when the object is missing', () => {
    expect(classifyAttestation('packed', undefined)).toBe('self');
  });

  it('reports self attestation for packed when the object cannot be decoded', () => {
    expect(classifyAttestation('packed', new Uint8Array([0xff, 0xff, 0xff]))).toBe('self');
  });
});
