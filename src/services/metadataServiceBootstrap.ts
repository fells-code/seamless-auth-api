/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { MetadataService } from '@simplewebauthn/server';

import { conformanceModeEnabled } from '../config/conformanceMode.js';
import { getSystemConfig } from '../config/getSystemConfig.js';
import getLogger from '../utils/logger.js';
import {
  allowListNeedsAttestation,
  requireKnownNeedsAttestation,
} from './authenticatorPolicyService.js';
import { applyConformanceMetadataOverrides } from './conformanceMetadata.js';

const logger = getLogger('metadataService');

let initialized = false;
let lastAttemptAt = 0;

/**
 * How long a failed initialisation is left alone before another registration retries it.
 *
 * A blob that cannot be fetched must not turn every registration into an outbound
 * request, and a policy enabled at runtime must not wait for a restart, so the retry is
 * throttled rather than either abandoned or unbounded.
 */
const RETRY_INTERVAL_MS = 5 * 60 * 1000;

/**
 * Whether the FIDO Metadata Service is available to validate attestations against.
 *
 * False either because this deployment does not request attestation, or because
 * the blob could not be fetched at startup.
 */
export function isMetadataServiceReady() {
  return initialized;
}

/** Test seam. Startup calls this once, so state has to be resettable. */
export function resetMetadataServiceForTests() {
  initialized = false;
  lastAttemptAt = 0;
}

/**
 * Brings the metadata service up if the current policy needs it and it is not ready.
 *
 * `authenticator_policy` is editable at runtime, and this used to be read once at
 * startup. An operator who turned attestation on afterwards got half a policy:
 * `evaluateAuthenticatorPolicy` reads fresh config and still refused a credential that
 * could not be traced to a manufacturer, but the metadata lookup that refuses a model
 * the blob does not list never ran, because the service had never been initialised. The
 * setting was accepted, nothing said it was inert, and the half that stopped applying
 * failed permissive.
 *
 * Called on the registration path so it takes effect on every instance without a
 * restart. A no-op once the service is up, and throttled when it is not, so a
 * deployment that does not ask for attestation pays one comparison.
 */
export async function ensureMetadataServiceReady(now = Date.now()): Promise<boolean> {
  if (initialized) {
    return true;
  }

  if (now - lastAttemptAt < RETRY_INTERVAL_MS) {
    return false;
  }

  return initializeMetadataService(now);
}

/**
 * Whether the FIDO Metadata Service holds a statement for this authenticator
 * model.
 *
 * This is the question `attestationVerified` is supposed to answer. Asking the
 * service directly is the only honest way to answer it: the library consults
 * metadata inside the individual attestation verifiers, and only for a statement
 * that carries a certificate chain, so a self attested or unattested credential
 * reaches this server having never been looked up.
 *
 * Never throws. Under a `strict` verification mode `getStatement` raises for an
 * unlisted model, which here is an answer rather than a failure.
 */
export async function hasMetadataStatement(aaguid: string | null | undefined): Promise<boolean> {
  if (!isMetadataServiceReady() || !aaguid) {
    return false;
  }

  try {
    return Boolean(await MetadataService.getStatement(aaguid));
  } catch (error) {
    logger.info(`No metadata statement for aaguid ${aaguid}: ${error}`);
    return false;
  }
}

/**
 * Prepares attestation validation against the FIDO Metadata Service.
 *
 * Only does anything when the deployment asks for attestation. Under the default
 * `none` there is no statement to validate, so downloading the blob would be a
 * network dependency at boot bought for nothing.
 *
 * Never throws. A metadata blob that cannot be fetched is a degraded state, not a
 * reason an authentication server should refuse to start, so the failure is
 * logged and registration continues without metadata validation. `requireKnown`
 * is deliberately not honoured in that case, because refusing every registration
 * on a transient network failure is worse than the risk it guards against.
 * `isMetadataServiceReady` reports which state the process is in.
 */
export async function initializeMetadataService(now = Date.now()): Promise<boolean> {
  lastAttemptAt = now;

  let attestation: string;
  let requireKnown: boolean;

  try {
    const { authenticator_policy } = await getSystemConfig();
    attestation = authenticator_policy.attestation;
    requireKnown = authenticator_policy.requireKnownAuthenticator;

    // An allow list matches on AAGUID, and an authenticator that was never asked
    // to identify itself does not report a usable one, so this combination
    // refuses every registration. Said once at startup rather than discovered
    // one failed enrolment at a time.
    if (allowListNeedsAttestation(authenticator_policy)) {
      logger.error(
        'authenticator_policy sets aaguidAllowList while attestation is "none". No authenticator ' +
          'can identify itself, so every registration will be refused. Set attestation to "direct".',
      );
    }

    // Said out loud for the same reason: the setting reads like it is doing
    // something, and under 'none' it is not.
    if (requireKnownNeedsAttestation(authenticator_policy)) {
      logger.error(
        'authenticator_policy sets requireKnownAuthenticator while attestation is "none". No ' +
          'authenticator identifies itself, so nothing can be matched against the metadata ' +
          'service and the setting has no effect. Set attestation to "direct".',
      );
    }
  } catch (error) {
    logger.error(`Could not read the authenticator policy, skipping metadata setup: ${error}`);
    return false;
  }

  // A conformance run drives attestation through its own surface, which honours
  // the conveyance the tools ask for rather than the deployment policy, so the
  // metadata tests need the service up whatever this deployment has configured.
  const conformance = conformanceModeEnabled();

  if (attestation !== 'direct' && !conformance) {
    logger.info('Attestation is not requested, so the metadata service is not initialized.');
    return false;
  }

  try {
    await MetadataService.initialize({
      // 'strict' makes the library refuse an authenticator the blob does not
      // list; 'permissive' registers it anyway.
      verificationMode: requireKnown ? 'strict' : 'permissive',
      ...(conformance ? applyConformanceMetadataOverrides() : {}),
    });

    initialized = true;
    logger.info(
      `Metadata service ready, unlisted authenticators are ${requireKnown ? 'refused' : 'allowed'}.`,
    );

    return true;
  } catch (error) {
    initialized = false;
    logger.error(
      `Metadata service failed to initialize, attestation will be verified without it: ${error}`,
    );

    return false;
  }
}
