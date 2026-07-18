import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/**/*.spec.ts'],

    // Model mocks in tests/setup/mocks.ts are shared module singletons. Running spec files in
    // parallel forks lets one file's mock return values bleed into another's, so the full
    // suite flakes on a different spec each run even though every spec passes in isolation.
    // The coverage script already runs sequentially for this reason; do it for every run so
    // results are deterministic. The suite is small, so the wall-clock cost is minor.
    fileParallelism: false,

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
