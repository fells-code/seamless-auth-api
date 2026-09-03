/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import {
  MetadataService,
  SettingsService,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import { isoCBOR } from '@simplewebauthn/server/helpers';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

import { SUPPORTED_ALGORITHM_IDS } from '../../../src/lib/webauthnAlgorithms';

// The library's own verifiers are what a conformance run exercises, and the
// shared setup stubs them out.
vi.unmock('@simplewebauthn/server');

const FIXTURE_DIR = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../fixtures/attestation',
);

interface Fixture {
  format: string;
  aaguid: string;
  expectedChallenge: string;
  expectedOrigin: string;
  expectedRPID: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  response: any;
}

function load(name: string): Fixture {
  return JSON.parse(fs.readFileSync(path.join(FIXTURE_DIR, `${name}.json`), 'utf8'));
}

function verify(fixture: Fixture) {
  return verifyRegistrationResponse({
    response: fixture.response,
    expectedChallenge: fixture.expectedChallenge,
    expectedOrigin: fixture.expectedOrigin,
    expectedRPID: fixture.expectedRPID,
    requireUserVerification: false,
    supportedAlgorithmIDs: SUPPORTED_ALGORITHM_IDS,
  });
}

/**
 * The same statement with one byte of the signature flipped.
 *
 * Re-encoding the attestation object rather than corrupting the base64url keeps
 * the response well formed, so what the verifier rejects is the cryptography and
 * not the framing.
 */
function withTamperedSignature(fixture: Fixture): Fixture {
  const decoded = isoCBOR.decodeFirst<Map<string, unknown>>(
    new Uint8Array(Buffer.from(fixture.response.response.attestationObject, 'base64url')),
  );

  const attStmt = decoded.get('attStmt') as Map<string, unknown>;
  const signature = Uint8Array.from(attStmt.get('sig') as Uint8Array);
  signature[signature.length - 1] ^= 0xff;
  attStmt.set('sig', signature);

  const reencoded = isoCBOR.encode(decoded as never);

  return {
    ...fixture,
    response: {
      ...fixture.response,
      response: {
        ...fixture.response.response,
        attestationObject: Buffer.from(reencoded).toString('base64url'),
      },
    },
  };
}

/** The same statement with the authenticator data corrupted instead. */
function withTamperedAuthData(fixture: Fixture): Fixture {
  const decoded = isoCBOR.decodeFirst<Map<string, unknown>>(
    new Uint8Array(Buffer.from(fixture.response.response.attestationObject, 'base64url')),
  );

  const authData = Uint8Array.from(decoded.get('authData') as Uint8Array);
  // The RP ID hash, which the relying party check catches ahead of any
  // signature. The signature counter looks like the more natural target and is
  // the wrong one: fido-u2f signs an explicit list of fields rather than the
  // authenticator data as a whole, and the counter is not on that list, so
  // moving it verifies happily. Signature coverage is what the tampered
  // signature case above exercises.
  authData[0] ^= 0xff;
  decoded.set('authData', authData);

  return {
    ...fixture,
    response: {
      ...fixture.response,
      response: {
        ...fixture.response.response,
        attestationObject: Buffer.from(isoCBOR.encode(decoded as never)).toString('base64url'),
      },
    },
  };
}

async function refuses(fixture: Fixture) {
  try {
    const result = await verify(fixture);
    return result.verified === false;
  } catch {
    return true;
  }
}

describe('attestation formats, against statements captured from the FIDO conformance tools', () => {
  // FIDO Server Requirements v2.3 names Packed, TPM, U2F and Android SafetyNet.
  // SafetyNet is absent on purpose, see the final describe block for why.
  describe.each([
    { name: 'packed', aaguid: '326adcf0-0cef-46d0-9392-98d6c4a84a72' },
    { name: 'tpm', aaguid: 'a7d6d93a-8a0d-11e8-9a94-a6cf71072f73' },
    { name: 'fido-u2f', aaguid: '00000000-0000-0000-0000-000000000000' },
  ])('$name', ({ name, aaguid }) => {
    it('verifies, and reports the format and model it came from', async () => {
      const result = await verify(load(name));

      expect(result.verified).toBe(true);
      expect(result.registrationInfo?.fmt).toBe(name);
      expect(result.registrationInfo?.aaguid).toBe(aaguid);
    });

    it('is refused once the attestation signature is tampered with', async () => {
      expect(await refuses(withTamperedSignature(load(name)))).toBe(true);
    });

    it('is refused once the authenticator data is tampered with', async () => {
      expect(await refuses(withTamperedAuthData(load(name)))).toBe(true);
    });
  });

  describe('android-key, whose chain only validates against the conformance roots', () => {
    let productionRoots: string[];

    beforeAll(() => {
      productionRoots = SettingsService.getRootCertificates({ identifier: 'android-key' });
    });

    afterAll(() => {
      SettingsService.setRootCertificates({
        identifier: 'android-key',
        certificates: productionRoots,
      });
    });

    it('is refused against the real Google roots', async () => {
      SettingsService.setRootCertificates({
        identifier: 'android-key',
        certificates: productionRoots,
      });

      await expect(verify(load('android-key'))).rejects.toThrow(/root certificate/i);
    });

    it('verifies once the preset roots are cleared, which is what conformance mode does', async () => {
      SettingsService.setRootCertificates({ identifier: 'android-key', certificates: [] });

      const result = await verify(load('android-key'));

      expect(result.verified).toBe(true);
      expect(result.registrationInfo?.fmt).toBe('android-key');
    });
  });

  describe('an authenticator the metadata service does not list', () => {
    // No mdsServers and no statements: the blob is never fetched, and the
    // fixture's model is absent by construction rather than by network luck.
    async function initializeMetadata(verificationMode: 'strict' | 'permissive') {
      await MetadataService.initialize({ mdsServers: [], statements: [], verificationMode });
    }

    it('is refused when requireKnownAuthenticator is on', async () => {
      await initializeMetadata('strict');

      await expect(verify(load('packed'))).rejects.toThrow(/No metadata statement found/i);
    });

    it('registers without a metadata statement when requireKnownAuthenticator is off', async () => {
      await initializeMetadata('permissive');

      const result = await verify(load('packed'));

      expect(result.verified).toBe(true);
      await expect(MetadataService.getStatement(load('packed').aaguid)).resolves.toBeUndefined();
    });
  });

  describe('android-safetynet', () => {
    // Not covered, and not coverable by a fixture. Two independent reasons:
    //
    // The conformance tools never send one. Three runs on 2026-09-02 and
    // 2026-09-03, with every test group selected, produced no SafetyNet
    // statement at all, though its metadata statement loads with the rest.
    //
    // Even given one, the verifier refuses a SafetyNet statement more than
    // sixty seconds after the authenticator produced it, so a committed fixture
    // would be dead on arrival and could only pass with a faked clock, which
    // proves nothing about the format.
    //
    // Tracked on #210 rather than left implicit here.
    it.todo('is exercised against a real statement');
  });
});
