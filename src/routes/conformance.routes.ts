/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { conformanceModeEnabled } from '../config/conformanceMode.js';
import {
  assertionOptions,
  assertionResult,
  attestationOptions,
  attestationResult,
} from '../controllers/conformance.js';
import { createRouter } from '../lib/createRouter.js';
import getLogger from '../utils/logger.js';

const logger = getLogger('conformance');

const conformanceRouter = createRouter('/conformance');

// Guarded here rather than inside the handlers so that with the flag unset the
// router is empty: nothing is registered with Express, nothing reaches the
// OpenAPI document, and the paths fall through to the ordinary 404. A handler
// that answers 403 would still be an admission that the surface exists.
if (conformanceModeEnabled()) {
  logger.warn(
    'FIDO2 conformance interface is mounted at /conformance. This surface bypasses ' +
      'authentication by design and must never be enabled in a customer deployment.',
  );

  // No request or response schemas: the tools send deliberately malformed bodies
  // and expect the conformance envelope back, not a Zod error, so validation and
  // the shape of a refusal both belong in the controller.
  conformanceRouter.post(
    '/attestation/options',
    { summary: 'FIDO2 conformance: registration options', tags: ['Conformance'] },
    attestationOptions,
  );

  conformanceRouter.post(
    '/attestation/result',
    { summary: 'FIDO2 conformance: registration result', tags: ['Conformance'] },
    attestationResult,
  );

  conformanceRouter.post(
    '/assertion/options',
    { summary: 'FIDO2 conformance: authentication options', tags: ['Conformance'] },
    assertionOptions,
  );

  conformanceRouter.post(
    '/assertion/result',
    { summary: 'FIDO2 conformance: authentication result', tags: ['Conformance'] },
    assertionResult,
  );
}

export default conformanceRouter.router;
