import { PrismaClient } from '@ctem/db';

const OWNER_URL = 'postgresql://ctem:ctem@localhost:5432/ctem?schema=public';
const APP_URL = 'postgresql://ctem_app:ctem_app@localhost:5432/ctem?schema=public';

/**
 * Connection as the migration owner (superuser in dev). Bypasses row-level
 * security — use it for arranging fixtures and cleaning up, never to test
 * tenant-facing behavior.
 */
export function ownerClient(): PrismaClient {
  return new PrismaClient({
    datasources: { db: { url: process.env.DATABASE_URL ?? OWNER_URL } },
  });
}

/**
 * Connection as `ctem_app`, the role the services actually run under. RLS
 * applies to every query. This is the client to use when asserting isolation.
 */
export function appClient(): PrismaClient {
  return new PrismaClient({
    datasources: { db: { url: process.env.DATABASE_APP_URL ?? APP_URL } },
  });
}

type Tx = Parameters<Parameters<PrismaClient['$transaction']>[0]>[0];

/** Standalone equivalent of PrismaService.withOrg for arbitrary test clients. */
export async function withOrg<T>(
  client: PrismaClient,
  orgId: string,
  fn: (tx: Tx) => Promise<T>,
): Promise<T> {
  return client.$transaction(async (tx) => {
    await tx.$executeRawUnsafe(`SELECT set_config('app.current_org_id', $1, true)`, orgId);
    return fn(tx);
  });
}
