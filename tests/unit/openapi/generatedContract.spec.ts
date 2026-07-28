import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { buildOpenApiDocument } from '../../../src/scripts/generateApiTypes.js';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '../../..');

function readCommitted(relativePath: string) {
  return readFileSync(join(repoRoot, relativePath), 'utf8');
}

describe('generated API contract', () => {
  it('keeps openapi.json in step with the route definitions', async () => {
    const generated = await buildOpenApiDocument();
    const committed = JSON.parse(readCommitted('openapi.json'));

    // The version tracks package.json, which Changesets bumps on release without
    // regenerating. Everything else must match.
    expect({ ...generated, info: undefined }).toEqual({ ...committed, info: undefined });
  });

  it('ships non-empty generated types', () => {
    const types = readCommitted('src/generated/api.ts');

    expect(types).not.toContain('export type paths = Record<string, never>');
    expect(types).toContain('export interface paths');
    expect(types).toContain('/users/me');
  });
});
