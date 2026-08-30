/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { MetadataService } from '@simplewebauthn/server';

import { getSystemConfig } from '../config/getSystemConfig.js';
import getLogger from '../utils/logger.js';

const logger = getLogger('metadataService');

let initialized = false;

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
export async function initializeMetadataService(): Promise<boolean> {
  let attestation: string;
  let requireKnown: boolean;

  try {
    const { authenticator_policy } = await getSystemConfig();
    attestation = authenticator_policy.attestation;
    requireKnown = authenticator_policy.requireKnownAuthenticator;
  } catch (error) {
    logger.error(`Could not read the authenticator policy, skipping metadata setup: ${error}`);
    return false;
  }

  if (attestation !== 'direct') {
    logger.info('Attestation is not requested, so the metadata service is not initialized.');
    return false;
  }

  try {
    await MetadataService.initialize({
      // 'strict' makes the library refuse an authenticator the blob does not
      // list; 'permissive' registers it anyway.
      verificationMode: requireKnown ? 'strict' : 'permissive',
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
