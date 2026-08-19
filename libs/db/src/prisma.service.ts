import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';
import { loadEnv } from '@ctem/config';
import { getContext, rootLogger } from '@ctem/observability';

/**
 * Prisma client with tenancy enforced at the database, not in application code.
 *
 * `withOrg` opens a transaction, sets the `app.current_org_id` GUC for its
 * duration, and runs the callback. Row-level security does the rest. Repositories
 * should never build `where: { orgId }` clauses by hand for isolation — that is
 * defense in depth at best and a data leak at worst.
 */
@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit, OnModuleDestroy {
  private readonly log = rootLogger.child({ component: 'prisma' });

  constructor() {
    const env = loadEnv();
    super({
      datasources: { db: { url: env.DATABASE_APP_URL ?? env.DATABASE_URL } },
      log: env.NODE_ENV === 'development' ? ['warn', 'error'] : ['error'],
    });
  }

  async onModuleInit(): Promise<void> {
    await this.$connect();
    this.log.info('database connected');
  }

  async onModuleDestroy(): Promise<void> {
    await this.$disconnect();
  }

  /** Runs `fn` inside a transaction scoped to a single organization. */
  async withOrg<T>(orgId: string, fn: (tx: PrismaTransaction) => Promise<T>): Promise<T> {
    return this.$transaction(async (tx: PrismaTransaction) => {
      // set_config with is_local=true so the setting is rolled back with the tx.
      await tx.$executeRawUnsafe(`SELECT set_config('app.current_org_id', $1, true)`, orgId);
      return fn(tx as PrismaTransaction);
    });
  }

  /** Uses the org from the ambient request context; throws if there isn't one. */
  async withCurrentOrg<T>(fn: (tx: PrismaTransaction) => Promise<T>): Promise<T> {
    const orgId = getContext()?.orgId;
    if (!orgId) throw new Error('withCurrentOrg called outside an org-scoped request context');
    return this.withOrg(orgId, fn);
  }

  /**
   * Escape hatch for cross-tenant work (feed ingestion, platform admin jobs).
   * Deliberately verbose so it shows up in code review.
   */
  async unsafeCrossTenant<T>(reason: string, fn: (client: PrismaClient) => Promise<T>): Promise<T> {
    this.log.warn({ reason }, 'cross-tenant database access');
    return fn(this);
  }
}

export type PrismaTransaction = Omit<
  PrismaClient,
  '$connect' | '$disconnect' | '$on' | '$transaction' | '$use' | '$extends'
>;
