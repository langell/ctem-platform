-- Durable scan.kick meter. One row per accepted scan, inserted in the same
-- transaction as the scan. Idempotency-Key / CI external_id is unique per org
-- when present. NULL keys do not collide (schedule uses the leader lease,
-- cadence, and a unique scanId).

-- CreateTable
CREATE TABLE "scan_kicks" (
    "eventId" UUID NOT NULL,
    "orgId" UUID NOT NULL,
    "scanId" UUID NOT NULL,
    "source" TEXT NOT NULL,
    "scannerTypes" TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    "occurredAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "idempotencyKey" TEXT,

    CONSTRAINT "scan_kicks_pkey" PRIMARY KEY ("eventId")
);

-- CreateIndex
CREATE UNIQUE INDEX "scan_kicks_scanId_key" ON "scan_kicks"("scanId");

-- CreateIndex
CREATE UNIQUE INDEX "scan_kicks_orgId_idempotencyKey_key" ON "scan_kicks"("orgId", "idempotencyKey");

-- CreateIndex
CREATE INDEX "scan_kicks_orgId_occurredAt_idx" ON "scan_kicks"("orgId", "occurredAt");

-- AddForeignKey
ALTER TABLE "scan_kicks" ADD CONSTRAINT "scan_kicks_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "scan_kicks" ADD CONSTRAINT "scan_kicks_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "scans"("id") ON DELETE CASCADE ON UPDATE CASCADE;
