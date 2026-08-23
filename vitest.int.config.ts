import { defineConfig } from 'vitest/config';
import { workspaceAliases } from './vitest.alias';

/**
 * Integration tier: real Postgres (with RLS), real crypto, real HTTP.
 * Requires the docker-compose stack: `make infra && make db-migrate`.
 *
 * Files run sequentially — suites arrange tenant fixtures in a shared database
 * and parallel files would race on it.
 */
export default defineConfig({
  test: {
    include: ['{apps,libs}/**/*.int.spec.ts'],
    exclude: ['**/node_modules/**', '**/dist/**'],
    environment: 'node',
    setupFiles: ['./tools/testing/int-setup.ts'],
    fileParallelism: false,
    testTimeout: 30_000,
    hookTimeout: 60_000,
  },
  resolve: {
    alias: workspaceAliases,
  },
});
