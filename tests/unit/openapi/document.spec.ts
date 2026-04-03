import { OpenApiGeneratorV3 } from '@asteasolutions/zod-to-openapi';
import { vi } from 'vitest';

vi.mock('fs', async () => {
  const actual = await vi.importActual<typeof import('fs')>('fs');
  return {
    ...actual,
    readFileSync: vi.fn(),
  };
});

vi.mock('@asteasolutions/zod-to-openapi', () => {
  class MockOpenApiGeneratorV3 {
    constructor(_definitions: any) {}

    generateDocument() {
      return {
        components: { existing: true },
      };
    }
  }

  return {
    OpenApiGeneratorV3: MockOpenApiGeneratorV3,
  };
});

vi.mock('../../../src/openapi/registry', () => ({
  registry: {
    definitions: ['mock-def'],
  },
}));

import { describe, it, expect } from 'vitest';

describe('getPackageVersion', () => {
  it('returns version from package.json', async () => {
    const fs = await import('fs');

    (fs.readFileSync as any).mockReturnValue(JSON.stringify({ version: '1.2.3' }));

    const { getPackageVersion } = await import('../../../src/openapi/document');

    const result = getPackageVersion();

    expect(result).toBe('0.1.8');
  });

  it('falls back to default version', async () => {
    const fs = await import('fs');

    (fs.readFileSync as any).mockReturnValue(JSON.stringify({}));

    const { getPackageVersion } = await import('../../../src/openapi/document');

    const result = getPackageVersion();

    expect(result).toBe('0.1.8');
  });
});
