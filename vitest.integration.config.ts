import { defineConfig } from 'vitest/config'

/**
 * Vitest configuration for integration tests.
 *
 * Runs API and repository integration tests against a real PostgreSQL database
 * (Testcontainers Docker or external TEST_DATABASE_URL).
 *
 * Usage:
 *   npx vitest run --config vitest.integration.config.ts
 *   TEST_DATABASE_URL=postgresql://... npx vitest run --config vitest.integration.config.ts
 */
export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    // repositories.test.ts uses node:test format – excluded here (run separately)
    include: ['tests/integration/api.test.ts'],
    // Testcontainers can take up to 30 s to pull and start on first run
    testTimeout: 60_000,
    hookTimeout: 90_000,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html', 'lcov'],
      include: ['src/**/*.ts'],
      exclude: [
        'src/**/*.test.ts',
        'src/**/*.spec.ts',
        'src/**/__tests__/**',
        'src/index.ts',
      ],
      thresholds: {
        statements: 80,
        branches: 80,
        functions: 80,
        lines: 80,
      },
    },
  },
})
