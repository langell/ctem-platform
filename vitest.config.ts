import { defineConfig } from 'vitest/config';
import { workspaceAliases } from './vitest.alias';

/**
 * Unit tier: pure logic, no infra, runs in seconds. Anything named
 * `*.int.spec.ts` belongs to the integration tier (vitest.int.config.ts).
 */
export default defineConfig({
  test: {
    include: ['{apps,libs}/**/*.spec.ts'],
    exclude: ['**/node_modules/**', '**/dist/**', '**/*.int.spec.ts'],
    environment: 'node',
    passWithNoTests: true,
  },
  resolve: {
    alias: workspaceAliases,
  },
});
