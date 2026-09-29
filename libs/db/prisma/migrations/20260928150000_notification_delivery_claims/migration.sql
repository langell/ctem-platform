-- Durable at-most-once claim for a successful policy.violated Slack or Jira
-- send. One row per (org, finding, policy, channel). A failed send deletes the
-- row so JetStream redelivery can claim again. Redis is not the source of truth.
-- findingId / policyId are not foreign keys: the seed KEV/critical rule publishes
-- a policy id that is not a policies row.

-- CreateTable
CREATE TABLE "notification_delivery_claims" (
    "id" UUID NOT NULL,
    "orgId" UUID NOT NULL,
    "findingId" UUID NOT NULL,
    "policyId" UUID NOT NULL,
    "channel" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "notification_delivery_claims_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "notification_delivery_claims_uniq" ON "notification_delivery_claims"("orgId", "findingId", "policyId", "channel");

-- AddForeignKey
ALTER TABLE "notification_delivery_claims" ADD CONSTRAINT "notification_delivery_claims_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;
