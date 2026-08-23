/**
 * Seeds a demo organization so `make db-seed && make dev` gives you something to
 * look at. The actual entity builders live in @ctem/testing so the test suites
 * and this seed can never drift apart.
 */
import { PrismaClient } from '../src/generated/client';
import { seedDemoOrg } from '@ctem/testing';

const prisma = new PrismaClient();

seedDemoOrg(prisma)
  .then(({ org, assets }) => {
    console.log(`seeded org ${org.slug} (${org.id}) with ${assets.length} assets`);
  })
  .catch((err) => {
    console.error(err);
    process.exit(1);
  })
  .finally(() => prisma.$disconnect());
