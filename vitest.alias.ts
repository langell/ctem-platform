import { resolve } from 'node:path';

/** Source-level aliases shared by the unit and integration vitest configs. */
export const workspaceAliases = {
  '@ctem/contracts': resolve(__dirname, 'libs/contracts/src/index.ts'),
  '@ctem/config': resolve(__dirname, 'libs/config/src/index.ts'),
  '@ctem/observability': resolve(__dirname, 'libs/observability/src/index.ts'),
  '@ctem/events': resolve(__dirname, 'libs/events/src/index.ts'),
  '@ctem/db': resolve(__dirname, 'libs/db/src/index.ts'),
  '@ctem/auth': resolve(__dirname, 'libs/auth/src/index.ts'),
  '@ctem/storage': resolve(__dirname, 'libs/storage/src/index.ts'),
  '@ctem/service-kit': resolve(__dirname, 'libs/service-kit/src/index.ts'),
  '@ctem/scanner-sdk': resolve(__dirname, 'libs/scanner-sdk/src/index.ts'),
  '@ctem/testing': resolve(__dirname, 'libs/testing/src/index.ts'),
  '@ctem/vuln-intel': resolve(__dirname, 'libs/vuln-intel/src/index.ts'),
};
