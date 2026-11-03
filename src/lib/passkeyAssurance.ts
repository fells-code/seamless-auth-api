/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import type { CredentialDeviceType } from '@simplewebauthn/server';

interface RegisteredCredential {
  deviceType: CredentialDeviceType | null;
  attestationVerified: boolean | null;
}

/**
 * The hardware assurance a passkey assertion earns, or null when the assertion's backup
 * eligibility differs from the one registered.
 *
 * WebAuthn Level 3 fixes the backup eligibility flag at registration, so an assertion that
 * reports another value did not come from the authenticator that registered. The flag is
 * self-reported under `none` attestation, so only a registration whose attestation was
 * verified against metadata can claim a device-bound key.
 *
 * A credential registered before the device type was stored has nothing to compare with,
 * and earns no hardware assurance.
 */
export function passkeyDeviceBinding(
  credential: RegisteredCredential,
  reported: CredentialDeviceType,
): { deviceBound: boolean } | null {
  if (credential.deviceType && credential.deviceType !== reported) {
    return null;
  }

  return {
    deviceBound:
      credential.deviceType === 'singleDevice' && credential.attestationVerified === true,
  };
}
