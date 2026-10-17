import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { getAdapterManifest } from '../../../src/lib/adapterManifest.js';
import { buildOpenApiDocument } from '../../../src/scripts/generateApiTypes.js';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '../../..');

function readCommitted(relativePath: string) {
  return readFileSync(join(repoRoot, relativePath), 'utf8');
}

const packageVersion = JSON.parse(readCommitted('package.json')).version;

describe('generated API contract', () => {
  it('keeps openapi.json in step with the route definitions', async () => {
    const generated = await buildOpenApiDocument();
    const committed = JSON.parse(readCommitted('openapi.json'));

    expect(committed).toEqual(generated);
  });

  it('versions openapi.json with the package', () => {
    expect(JSON.parse(readCommitted('openapi.json')).info.version).toBe(packageVersion);
  });

  it('keeps adapter-manifest.json in step with the route definitions', async () => {
    await buildOpenApiDocument();
    const committed = JSON.parse(readCommitted('adapter-manifest.json'));

    expect(committed).toEqual(JSON.parse(JSON.stringify(getAdapterManifest())));
    expect(committed.apiVersion).toBe(packageVersion);
  });

  it('ships non-empty generated types', () => {
    const types = readCommitted('src/generated/api.ts');

    expect(types).not.toContain('export type paths = Record<string, never>');
    expect(types).toContain('export interface paths');
    expect(types).toContain('/users/me');
  });
});
