import path from 'path';
import { fileURLToPath } from 'url';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { loadRoutes } from '../../../src/lib/loadRoutes.js';

const fixturesDir = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '__fixtures__/loadRoutes',
);

describe('loadRoutes', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('mounts routers with a default export and skips non-route and export-less files', async () => {
    const realResolve = path.resolve.bind(path);
    vi.spyOn(path, 'resolve').mockImplementation((...args: string[]) =>
      args[args.length - 1] === '../routes' ? fixturesDir : realResolve(...args),
    );
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});

    const use = vi.fn();
    const app = { use } as any;

    await loadRoutes(app);

    expect(use).toHaveBeenCalledTimes(1);
    expect(use).toHaveBeenCalledWith({ marker: 'good-router' });

    expect(warn).toHaveBeenCalledWith(
      expect.stringContaining('noDefault.routes.js has no default router export'),
    );
  });
});
