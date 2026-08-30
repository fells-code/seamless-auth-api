import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/**/*.spec.ts'],

    // mockClear() empties call history but leaves the mockResolvedValueOnce queue intact, so a
    // value queued by one test and never consumed is returned to a later, unrelated one. That
    // shifts every subsequent Once value by a place and shows up as a wrong status, a wrong
    // body, or a request that never settles. mockReset is what drains the queue.
    //
    // Mocks in tests/setup/mocks.ts must therefore pass their implementation to vi.fn() rather
    // than chain .mockResolvedValue(), because reset restores the former and drops the latter.
    mockReset: true,

    // Both stub kinds write to the process (process.env, globalThis), which isolate: true does
    // not roll back between files: it resets the module registry, not the worker. Without these
    // a stubbed NODE_ENV or a stubbed global fetch outlives the file that set it.
    unstubEnvs: true,
    unstubGlobals: true,

    // Headroom for the async supertest integration tests; a genuine hang still fails, later.
    testTimeout: 20000,
    hookTimeout: 20000,

    setupFiles: ['./tests/setup/env.ts', './tests/setup/mocks.ts'],

    globalSetup: ['./tests/setup/globalSetup.ts'],

    coverage: {
      provider: 'v8',

      reporter: ['text', 'html', 'lcov', 'json-summary'],

      reportsDirectory: './coverage',

      include: ['src/**/*.ts'],

      exclude: [
        'src/**/*.d.ts',
        'src/models/index.ts',
        'src/server.ts',
        // Type-only modules: emit no runtime JavaScript, so there is nothing to execute.
        'src/generated/api.ts',
        'src/types/types.ts',
        'src/lib/routeTypes.ts',
      ],

      thresholds: {
        lines: 98,
        functions: 98,
        branches: 95,
        statements: 98,
      },
    },
  },
});
