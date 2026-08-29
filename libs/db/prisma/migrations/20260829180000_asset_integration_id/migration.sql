-- AlterTable
ALTER TABLE "assets" ADD COLUMN "integrationId" UUID;

-- CreateIndex
CREATE INDEX "assets_orgId_integrationId_idx" ON "assets"("orgId", "integrationId");

-- AddForeignKey
ALTER TABLE "assets" ADD CONSTRAINT "assets_integrationId_fkey" FOREIGN KEY ("integrationId") REFERENCES "integrations"("id") ON DELETE SET NULL ON UPDATE CASCADE;
