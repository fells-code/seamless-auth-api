import { describe, expect, it } from 'vitest';

import {
  allowListNeedsAttestation,
  evaluateAuthenticatorPolicy,
} from '../../../src/services/authenticatorPolicyService.js';

const YUBIKEY = 'ee882879-721c-4913-9775-3dfcce97072a';
const ANONYMOUS = '00000000-0000-0000-0000-000000000000';

function policy(overrides: Record<string, unknown> = {}) {
  return {
    attachment: 'any',
    userVerification: 'required',
    attestation: 'direct',
    requireKnownAuthenticator: false,
    syncedPasskeys: 'allow',
    aaguidAllowList: [],
    aaguidDenyList: [],
    ...overrides,
  } as any;
}

describe('synced passkeys', () => {
  it('refuses a credential that can leave the device when blocked', () => {
    const verdict = evaluateAuthenticatorPolicy({
      policy: policy({ syncedPasskeys: 'block' }),
      aaguid: YUBIKEY,
      deviceType: 'multiDevice',
    });

    expect(verdict.allowed).toBe(false);
    expect(verdict.reason).toBe('synced_passkey_not_allowed');
  });

  it('admits a credential bound to one device', () => {
    const verdict = evaluateAuthenticatorPolicy({
      policy: policy({ syncedPasskeys: 'block' }),
      aaguid: YUBIKEY,
      deviceType: 'singleDevice',
    });

    expect(verdict.allowed).toBe(true);
  });

  // The exposure is that the key *can* leave, not that it already has, so a
  // backup-eligible credential is refused even before it syncs.
  it('judges eligibility rather than whether it has synced yet', () => {
    const verdict = evaluateAuthenticatorPolicy({
      policy: policy({ syncedPasskeys: 'block' }),
      aaguid: YUBIKEY,
      deviceType: 'multiDevice',
    });

    expect(verdict.allowed).toBe(false);
  });

  it('admits it when the deployment allows syncing', () => {
    const verdict = evaluateAuthenticatorPolicy({
      policy: policy({ syncedPasskeys: 'allow' }),
      aaguid: YUBIKEY,
      deviceType: 'multiDevice',
    });

    expect(verdict.allowed).toBe(true);
  });
});

describe('authenticator model lists', () => {
  it('restricts nothing when both lists are empty', () => {
    expect(
      evaluateAuthenticatorPolicy({ policy: policy(), aaguid: YUBIKEY, deviceType: 'singleDevice' })
        .allowed,
    ).toBe(true);
  });

  it('admits only listed models when an allow list is set', () => {
    const allowed = evaluateAuthenticatorPolicy({
      policy: policy({ aaguidAllowList: [YUBIKEY] }),
      aaguid: YUBIKEY,
      deviceType: 'singleDevice',
    });
    const refused = evaluateAuthenticatorPolicy({
      policy: policy({ aaguidAllowList: [YUBIKEY] }),
      aaguid: 'deadbeef-0000-0000-0000-000000000000',
      deviceType: 'singleDevice',
    });

    expect(allowed.allowed).toBe(true);
    expect(refused.allowed).toBe(false);
    expect(refused.reason).toBe('authenticator_not_allowed');
  });

  // Otherwise the list would be advisory: anything that declines to identify
  // itself would sail past it.
  it('refuses an authenticator that declined to identify itself against an allow list', () => {
    const verdict = evaluateAuthenticatorPolicy({
      policy: policy({ aaguidAllowList: [YUBIKEY] }),
      aaguid: ANONYMOUS,
      deviceType: 'singleDevice',
    });

    expect(verdict.allowed).toBe(false);
    expect(verdict.reason).toBe('authenticator_not_allowed');
  });

  it('applies the deny list before the allow list', () => {
    const verdict = evaluateAuthenticatorPolicy({
      policy: policy({ aaguidAllowList: [YUBIKEY], aaguidDenyList: [YUBIKEY] }),
      aaguid: YUBIKEY,
      deviceType: 'singleDevice',
    });

    expect(verdict.allowed).toBe(false);
    expect(verdict.detail).toContain('deny list');
  });

  it('compares case insensitively', () => {
    const verdict = evaluateAuthenticatorPolicy({
      policy: policy({ aaguidAllowList: [YUBIKEY.toUpperCase()] }),
      aaguid: YUBIKEY,
      deviceType: 'singleDevice',
    });

    expect(verdict.allowed).toBe(true);
  });
});

describe('allowListNeedsAttestation', () => {
  it('flags an allow list set without asking authenticators to identify themselves', () => {
    expect(
      allowListNeedsAttestation(policy({ aaguidAllowList: [YUBIKEY], attestation: 'none' })),
    ).toBe(true);
  });

  it('is satisfied once attestation is requested', () => {
    expect(
      allowListNeedsAttestation(policy({ aaguidAllowList: [YUBIKEY], attestation: 'direct' })),
    ).toBe(false);
  });

  it('does not flag a deployment with no allow list', () => {
    expect(allowListNeedsAttestation(policy({ attestation: 'none' }))).toBe(false);
  });
});
