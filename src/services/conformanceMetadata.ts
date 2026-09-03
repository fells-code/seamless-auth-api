/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import type { MetadataStatement } from '@simplewebauthn/server';
import { SettingsService } from '@simplewebauthn/server';
import fs from 'fs';
import path from 'path';

import getLogger from '../utils/logger.js';

const logger = getLogger('conformanceMetadata');

/**
 * Attestation formats whose preset root certificates have to be cleared.
 *
 * The tools sign their Apple, Android Key and SafetyNet statements with their
 * own test roots, so validating those against the real vendor roots fails every
 * one of those tests. Cleared, the library falls back to the roots carried in
 * the metadata statement, which is what a run supplies.
 */
const VENDOR_ROOT_IDENTIFIERS = ['apple', 'android-key', 'android-safetynet'] as const;

export interface ConformanceMetadataOverrides {
  /** MDS3 endpoints the tools stand up for a run. Undefined leaves the official server in place. */
  mdsServers?: string[];
  /** Statements loaded from disk. Not refreshed, which is what the tools expect. */
  statements?: MetadataStatement[];
}

/**
 * Points metadata verification at the conformance tools instead of the FIDO
 * Metadata Service.
 *
 * A conformance run issues its own MDS3 endpoints and signs the blobs with its
 * own root, so a server that only trusts the production MDS root fails every
 * metadata test with a certificate error. All three inputs are optional: give
 * only what a given run hands you.
 *
 * - `FIDO_CONFORMANCE_MDS_URLS`: comma separated MDS3 endpoints
 * - `FIDO_CONFORMANCE_MDS_ROOT_CERT_FILE`: PEM the run signs its blobs with
 * - `FIDO_CONFORMANCE_METADATA_DIR`: directory of metadata statement JSON files
 *
 * Never throws. A run that is misconfigured should surface as failed metadata
 * tests with a line in the log saying why, not as a server that will not boot.
 */
export function applyConformanceMetadataOverrides(): ConformanceMetadataOverrides {
  const overrides: ConformanceMetadataOverrides = {};

  const mdsServers = splitList(process.env.FIDO_CONFORMANCE_MDS_URLS);
  if (mdsServers.length > 0) {
    overrides.mdsServers = mdsServers;
    logger.info(`Conformance MDS endpoints in use: ${mdsServers.length}`);
  }

  const rootCert = readRootCertificate(process.env.FIDO_CONFORMANCE_MDS_ROOT_CERT_FILE);
  if (rootCert) {
    SettingsService.setRootCertificates({ identifier: 'mds', certificates: [rootCert] });
    logger.info('Conformance MDS root certificate installed, replacing the FIDO production root.');
  }

  for (const identifier of VENDOR_ROOT_IDENTIFIERS) {
    SettingsService.setRootCertificates({ identifier, certificates: [] });
  }
  logger.info(
    'Vendor attestation roots cleared, so conformance statements supply the trust anchor.',
  );

  const statements = readStatements(process.env.FIDO_CONFORMANCE_METADATA_DIR);
  if (statements.length > 0) {
    overrides.statements = statements;
    logger.info(`Loaded ${statements.length} local conformance metadata statements.`);
  }

  return overrides;
}

function splitList(value: string | undefined): string[] {
  return (value ?? '')
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
}

function readRootCertificate(file: string | undefined): string | undefined {
  if (!file) {
    return undefined;
  }

  try {
    return fs.readFileSync(file, 'utf8');
  } catch (error) {
    logger.error(`Could not read the conformance MDS root certificate at ${file}: ${error}`);
    return undefined;
  }
}

function readStatements(dir: string | undefined): MetadataStatement[] {
  if (!dir) {
    return [];
  }

  let files: string[];

  try {
    // Recursive because the tools' metadata download unzips to a nested
    // metadataStatements/ directory, and is meant to be dropped in unedited.
    files = fs
      .readdirSync(dir, { recursive: true })
      .map((entry) => entry.toString())
      .filter((file) => file.endsWith('.json'));
  } catch (error) {
    logger.error(`Could not read the conformance metadata directory ${dir}: ${error}`);
    return [];
  }

  const statements: MetadataStatement[] = [];

  for (const file of files) {
    try {
      const parsed = JSON.parse(fs.readFileSync(path.join(dir, file), 'utf8'));

      // The tools ship statements both bare and wrapped in an MDS entry. Accept
      // either, so an operator does not have to unwrap them by hand.
      const statement = parsed?.metadataStatement ?? parsed;

      if (statement && typeof statement === 'object') {
        statements.push(statement as MetadataStatement);
      }
    } catch (error) {
      logger.error(`Skipping unreadable conformance metadata statement ${file}: ${error}`);
    }
  }

  return statements;
}
