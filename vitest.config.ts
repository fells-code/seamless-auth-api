import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/**/*.spec.ts'],

    setupFiles: ['./tests/setup/env.ts', './tests/setup/mocks.ts'],

    globalSetup: ['./tests/setup/globalSetup.ts'],

    coverage: {
      provider: 'v8',

      reporter: ['text', 'html', 'lcov'],

      reportsDirectory: './coverage',

      include: ['src/**/*.ts'],

      exclude: ['src/**/*.d.ts', 'src/models/index.ts', 'src/server.ts'],

      thresholds: {
        lines: 70,
        functions: 70,
        branches: 65,
        statements: 70,
      },
    },
  },
});
