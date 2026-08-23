import { Injectable, OnModuleDestroy } from '@nestjs/common';
import { PrismaClient } from '@ctem/db';
import { loadEnv } from '@ctem/config';

/**
 * The one component allowed to write vulnerability intelligence. It connects as
 * the migration owner (DATABASE_URL) because ctem_app deliberately has no write
 * grants on the shared intel tables — see 000_rls.sql.
 */
@Injectable()
export class FeedStore extends PrismaClient implements OnModuleDestroy {
  constructor() {
    const env = loadEnv();
    super({ datasources: { db: { url: env.DATABASE_URL } } });
  }

  async onModuleDestroy(): Promise<void> {
    await this.$disconnect();
  }
}
