import { beforeEach, describe, expect, it, vi } from 'vitest';

const readFileSync = vi.fn();

vi.mock('fs', () => ({
  default: { readFileSync },
  readFileSync,
}));

vi.mock('../../../src/openapi/registry', () => ({
  registry: { definitions: [] },
}));

vi.mock('@asteasolutions/zod-to-openapi', () => ({
  OpenApiGeneratorV3: class {
    generateDocument() {
      return { components: {} };
    }
  },
}));

describe('getPackageVersion version resolution', () => {
  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();
  });

  it('returns the version declared in package.json', async () => {
    readFileSync.mockReturnValue(JSON.stringify({ version: '1.2.3' }));

    const { getPackageVersion } = await import('../../../src/openapi/document');

    expect(getPackageVersion()).toBe('1.2.3');
  });

  it('falls back to 0.0.0 when package.json has no version', async () => {
    readFileSync.mockReturnValue(JSON.stringify({}));

    const { getPackageVersion } = await import('../../../src/openapi/document');

    expect(getPackageVersion()).toBe('0.0.0');
  });

  // The value cannot change while the process runs, and it backs /health/version, which
  // takes no authentication, so reading it per call put a synchronous file read on the
  // event loop for every caller.
  it('reads package.json once however many times it is asked', async () => {
    readFileSync.mockReturnValue(JSON.stringify({ version: '1.2.3' }));

    const { getPackageVersion } = await import('../../../src/openapi/document');

    expect(getPackageVersion()).toBe('1.2.3');
    expect(getPackageVersion()).toBe('1.2.3');
    expect(getPackageVersion()).toBe('1.2.3');

    expect(readFileSync).toHaveBeenCalledTimes(1);
  });

  // Resolved from the module rather than the working directory, which is not the
  // repository root for a process started anywhere else.
  it('answers rather than throwing when package.json cannot be read', async () => {
    readFileSync.mockImplementation(() => {
      throw new Error('ENOENT');
    });

    const { getPackageVersion } = await import('../../../src/openapi/document');

    expect(getPackageVersion()).toBe('0.0.0');
  });
});
