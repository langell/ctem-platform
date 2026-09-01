/**
 * Seeds a demo organization so `make db-seed && make dev` gives you something to
 * look at. The actual entity builders live in @ctem/testing so the test suites
 * and this seed can never drift apart.
 */
import { PrismaClient } from '../src/generated/client';
import { DEMO_ORG_ID, seedDemoOrg } from '@ctem/testing';

const prisma = new PrismaClient();

seedDemoOrg(prisma)
  .then(({ org, assets }) => {
    console.log(`seeded org ${org.slug} (${org.id}) with ${assets.length} assets`);
    if (org.id !== DEMO_ORG_ID) {
      console.warn(
        `demo org id is ${org.id}, not the Keycloak-mapped ${DEMO_ORG_ID}; ` +
          '`make demo-token` JWTs will not match this database. Reset Postgres and re-seed.',
      );
    }
  })
  .catch((err) => {
    console.error(err);
    process.exit(1);
  })
  .finally(() => prisma.$disconnect());
