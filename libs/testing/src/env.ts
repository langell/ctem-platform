import { resetEnvCache } from '@ctem/config';

/**
 * Overrides process.env and clears the cached parsed environment so the next
 * `loadEnv()` picks up the new values. Call this BEFORE instantiating anything
 * that reads config (Nest modules, PrismaService, JwtVerifier).
 */
export function applyTestEnv(overrides: Record<string, string>): void {
  for (const [key, value] of Object.entries(overrides)) {
    process.env[key] = value;
  }
  resetEnvCache();
}
