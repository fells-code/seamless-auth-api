/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

/**
 * The COSE algorithms this server will register a credential for, most preferred
 * first. `pubKeyCredParams` is an ordered preference list, so the position of
 * each entry matters as much as its presence.
 *
 * FIDO Server Requirements v2.3 requires all four. RS1 is RSASSA-PKCS1-v1_5 with
 * SHA-1, which is why it sits last: it is advertised because the specification
 * requires support for it, and ordered so that no authenticator with a better
 * option available will ever choose it.
 *
 * Set explicitly rather than left to the library default, which is
 * `[-8, -7, -257]` and therefore omits RS1, and which could change under a minor
 * upgrade without anything here noticing.
 *
 * Shared with the conformance interface so a conformance run exercises the same
 * list the shipping registration path advertises, rather than a copy of it.
 */
export const SUPPORTED_ALGORITHM_IDS = [
  -8, // EdDSA
  -7, // ES256
  -257, // RS256
  -65535, // RS1
];
