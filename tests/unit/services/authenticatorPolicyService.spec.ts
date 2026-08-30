import { describe, expect, it } from 'vitest';

import {
  allowListNeedsAttestation,
  evaluateAuthenticatorPolicy,
  requireKnownNeedsAttestation,
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
      attestationType: 'basic',
    });

    expect(verdict.allowed).toBe(false);
    expect(verdict.reason).toBe('synced_passkey_not_allowed');
  });

  it('admits a credential bound to one device', () => {
    const verdict = evaluateAuthenticatorPolicy({
      policy: policy({ syncedPasskeys: 'block' }),
      aaguid: YUBIKEY,
      deviceType: 'singleDevice',
      attestationType: 'basic',
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
      attestationType: 'basic',
    });

    expect(verdict.allowed).toBe(false);
  });

  it('admits it when the deployment allows syncing', () => {
    const verdict = evaluateAuthenticatorPolicy({
      policy: policy({ syncedPasskeys: 'allow' }),
      aaguid: YUBIKEY,
      deviceType: 'multiDevice',
      attestationType: 'basic',
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
      attestationType: 'basic',
    });
    const refused = evaluateAuthenticatorPolicy({
      policy: policy({ aaguidAllowList: [YUBIKEY] }),
      aaguid: 'deadbeef-0000-0000-0000-000000000000',
      deviceType: 'singleDevice',
      attestationType: 'basic',
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
      attestationType: 'basic',
    });

    expect(verdict.allowed).toBe(false);
    expect(verdict.reason).toBe('authenticator_not_allowed');
  });

  it('applies the deny list before the allow list', () => {
    const verdict = evaluateAuthenticatorPolicy({
      policy: policy({ aaguidAllowList: [YUBIKEY], aaguidDenyList: [YUBIKEY] }),
      aaguid: YUBIKEY,
      deviceType: 'singleDevice',
      attestationType: 'basic',
    });

    expect(verdict.allowed).toBe(false);
    expect(verdict.detail).toContain('deny list');
  });

  it('compares case insensitively', () => {
    const verdict = evaluateAuthenticatorPolicy({
      policy: policy({ aaguidAllowList: [YUBIKEY.toUpperCase()] }),
      aaguid: YUBIKEY,
      deviceType: 'singleDevice',
      attestationType: 'basic',
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

describe('requireKnownAuthenticator', () => {
  // The metadata service is only consulted for a statement carrying a certificate
  // chain, so these are the credentials that would otherwise slip past the setting
  // entirely rather than being checked and admitted.
  it.each(['self', 'none'] as const)('refuses a %s attested credential', (attestationType) => {
    const verdict = evaluateAuthenticatorPolicy({
      policy: policy({ requireKnownAuthenticator: true, attestation: 'direct' }),
      aaguid: YUBIKEY,
      deviceType: 'singleDevice',
      attestationType,
    });

    expect(verdict.allowed).toBe(false);
    expect(verdict.reason).toBe('authenticator_not_allowed');
    expect(verdict.detail).toContain('metadata service');
  });

  it('admits a credential that presented a certificate chain', () => {
    const verdict = evaluateAuthenticatorPolicy({
      policy: policy({ requireKnownAuthenticator: true, attestation: 'direct' }),
      aaguid: YUBIKEY,
      deviceType: 'singleDevice',
      attestationType: 'basic',
    });

    expect(verdict.allowed).toBe(true);
  });

  // Under 'none' nothing presents a chain, so applying the rule would refuse every
  // registration rather than restricting anything.
  it('does not apply when attestation was never requested', () => {
    const verdict = evaluateAuthenticatorPolicy({
      policy: policy({ requireKnownAuthenticator: true, attestation: 'none' }),
      aaguid: YUBIKEY,
      deviceType: 'singleDevice',
      attestationType: 'none',
    });

    expect(verdict.allowed).toBe(true);
  });

  it('does not apply when the deployment did not ask for known authenticators', () => {
    const verdict = evaluateAuthenticatorPolicy({
      policy: policy({ requireKnownAuthenticator: false, attestation: 'direct' }),
      aaguid: YUBIKEY,
      deviceType: 'singleDevice',
      attestationType: 'self',
    });

    expect(verdict.allowed).toBe(true);
  });

  it('is judged before the deny list, since an unidentified model matches no list', () => {
    const verdict = evaluateAuthenticatorPolicy({
      policy: policy({
        requireKnownAuthenticator: true,
        attestation: 'direct',
        aaguidDenyList: [YUBIKEY],
      }),
      aaguid: YUBIKEY,
      deviceType: 'singleDevice',
      attestationType: 'self',
    });

    expect(verdict.detail).toContain('metadata service');
  });
});

describe('requireKnownNeedsAttestation', () => {
  it('flags known-authenticators-only set without asking them to identify themselves', () => {
    expect(
      requireKnownNeedsAttestation(
        policy({ requireKnownAuthenticator: true, attestation: 'none' }),
      ),
    ).toBe(true);
  });

  it('is satisfied once attestation is requested', () => {
    expect(
      requireKnownNeedsAttestation(
        policy({ requireKnownAuthenticator: true, attestation: 'direct' }),
      ),
    ).toBe(false);
  });

  it('does not flag a deployment that did not ask for known authenticators', () => {
    expect(
      requireKnownNeedsAttestation(
        policy({ requireKnownAuthenticator: false, attestation: 'none' }),
      ),
    ).toBe(false);
  });
});
