/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import type { AuthenticatorPolicy } from '@seamless-auth/types';

/** The all-zero AAGUID: an authenticator declining to say what it is. */
const ANONYMOUS_AAGUID = '00000000-0000-0000-0000-000000000000';

export type AuthenticatorRefusal = 'authenticator_not_allowed' | 'synced_passkey_not_allowed';

export interface AuthenticatorPolicyVerdict {
  allowed: boolean;
  reason?: AuthenticatorRefusal;
  /** Operator-facing detail. Goes to the audit trail, not to the caller. */
  detail?: string;
}

const ALLOWED: AuthenticatorPolicyVerdict = { allowed: true };

function normalize(aaguid: string | null | undefined) {
  return (aaguid ?? '').trim().toLowerCase();
}

function listed(list: string[], aaguid: string) {
  return list.some((entry) => normalize(entry) === aaguid);
}

/**
 * Decides whether a just-verified credential may be registered.
 *
 * Order matters. The deny list is applied first so a model can be excluded even
 * when a broad allow list would otherwise admit it, then the allow list, then
 * the synced posture. A refusal names which rule refused, so an operator reading
 * the audit trail can tell "this model is not permitted here" from "this
 * credential can leave the device".
 */
export function evaluateAuthenticatorPolicy(params: {
  policy: AuthenticatorPolicy;
  aaguid: string | null | undefined;
  /** WebAuthn backup eligibility. 'multiDevice' means the key can leave its authenticator. */
  deviceType: string | null | undefined;
}): AuthenticatorPolicyVerdict {
  const { policy } = params;
  const aaguid = normalize(params.aaguid);

  if (policy.aaguidDenyList.length > 0 && aaguid && listed(policy.aaguidDenyList, aaguid)) {
    return {
      allowed: false,
      reason: 'authenticator_not_allowed',
      detail: 'Authenticator model is on the deny list',
    };
  }

  if (policy.aaguidAllowList.length > 0) {
    // An authenticator that was not asked to identify itself, or that declined,
    // cannot satisfy an allow list. Admitting it would make the list advisory.
    if (!aaguid || aaguid === ANONYMOUS_AAGUID) {
      return {
        allowed: false,
        reason: 'authenticator_not_allowed',
        detail:
          'Authenticator did not identify itself, so it cannot be matched against the allow list',
      };
    }

    if (!listed(policy.aaguidAllowList, aaguid)) {
      return {
        allowed: false,
        reason: 'authenticator_not_allowed',
        detail: 'Authenticator model is not on the allow list',
      };
    }
  }

  // Judged on eligibility rather than current backup state: a credential that
  // can leave the device is the exposure, whether or not it already has.
  if (policy.syncedPasskeys === 'block' && params.deviceType === 'multiDevice') {
    return {
      allowed: false,
      reason: 'synced_passkey_not_allowed',
      detail: 'Credential is backup eligible, so its key can leave the authenticator',
    };
  }

  return ALLOWED;
}

/**
 * Whether an allow list has been set without asking authenticators to identify
 * themselves, in which case it refuses everything.
 */
export function allowListNeedsAttestation(policy: AuthenticatorPolicy) {
  return policy.aaguidAllowList.length > 0 && policy.attestation !== 'direct';
}
