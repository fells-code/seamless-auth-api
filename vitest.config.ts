import { defineConfig, type TestProjectInlineConfiguration } from 'vitest/config';

const unit: TestProjectInlineConfiguration = {
  extends: true,
  test: {
    name: 'unit',
    include: ['tests/**/*.spec.ts'],
    exclude: ['tests/postgres/**'],

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

    setupFiles: [
      './tests/setup/env.ts',
      './tests/setup/mocks.ts',
      './tests/setup/supertestServer.ts',
    ],
  },
};

// Runs against a real database built by the migration chain, with none of the shared
// mocks, so the triggers and raw SQL are exercised as deployed. Only with TEST_DB=postgres.
const postgres: TestProjectInlineConfiguration = {
  extends: true,
  test: {
    name: 'postgres',
    include: ['tests/postgres/**/*.spec.ts'],
    setupFiles: ['./tests/setup/env.ts'],
    globalSetup: ['./tests/postgres/globalSetup.ts'],
    // Every file shares the one database.
    fileParallelism: false,
    testTimeout: 30000,
    hookTimeout: 120000,
  },
};

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',

    projects: process.env.TEST_DB === 'postgres' ? [unit, postgres] : [unit],

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
