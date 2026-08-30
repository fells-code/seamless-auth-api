/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

/**
 * Fails when a changeset asks for a major bump.
 *
 * The package is pre-1.0 and stays there until that is a deliberate decision, not
 * a side effect of landing a breaking change. Under 0.x a minor bump is already
 * the conventional signal for one, so a `major` changeset does not communicate
 * anything extra; it just ships 1.0.0 by accident. Two of them had accumulated
 * before this check existed.
 *
 * Describe the break in the changeset body, as the existing ones do. When 1.0 is
 * actually wanted, delete this check in the same change that cuts it.
 */

import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const changesetDir = join(dirname(fileURLToPath(import.meta.url)), '../../.changeset');

const offenders = readdirSync(changesetDir)
  .filter((entry) => entry.endsWith('.md') && entry !== 'README.md')
  .filter((entry) =>
    /^\s*['"][^'"]+['"]\s*:\s*major\s*$/m.test(readFileSync(join(changesetDir, entry), 'utf8')),
  );

if (offenders.length > 0) {
  console.error(
    `Major changesets found, which would release 1.0.0:\n${offenders
      .map((entry) => `  .changeset/${entry}`)
      .join('\n')}\n\n` +
      'This package stays pre-1.0 until cutting 1.0 is a deliberate decision. Use minor,\n' +
      'which already signals a breaking change under 0.x, and describe the break in the body.',
  );
  process.exit(1);
}

console.log('No major changesets.');
