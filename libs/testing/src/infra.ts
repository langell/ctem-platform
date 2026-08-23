import { ownerClient } from './db';

/**
 * Fails fast with an actionable message when the docker-compose stack is not
 * running. Integration suites call this once per file from the shared setup.
 */
export async function requireInfra(): Promise<void> {
  const db = ownerClient();
  try {
    await db.$queryRaw`SELECT 1`;
  } catch (err) {
    throw new Error(
      `Local infra is not reachable (postgres on localhost:5432).\n` +
        `Start it with:  make infra && make db-migrate\n` +
        `Underlying error: ${(err as Error).message}`,
    );
  } finally {
    await db.$disconnect();
  }
}
