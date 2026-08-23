-- CreateTable
CREATE TABLE "vulnerability_affects" (
    "id" UUID NOT NULL,
    "vulnId" TEXT NOT NULL,
    "ecosystem" TEXT NOT NULL,
    "packageName" TEXT NOT NULL,

    CONSTRAINT "vulnerability_affects_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "vuln_package_sync" (
    "ecosystem" TEXT NOT NULL,
    "packageName" TEXT NOT NULL,
    "syncedAt" TIMESTAMP(3) NOT NULL,
    "advisories" INTEGER NOT NULL DEFAULT 0,

    CONSTRAINT "vuln_package_sync_pkey" PRIMARY KEY ("ecosystem","packageName")
);

-- CreateIndex
CREATE INDEX "vulnerability_affects_ecosystem_packageName_idx" ON "vulnerability_affects"("ecosystem", "packageName");

-- CreateIndex
CREATE UNIQUE INDEX "vulnerability_affects_vulnId_ecosystem_packageName_key" ON "vulnerability_affects"("vulnId", "ecosystem", "packageName");

-- AddForeignKey
ALTER TABLE "vulnerability_affects" ADD CONSTRAINT "vulnerability_affects_vulnId_fkey" FOREIGN KEY ("vulnId") REFERENCES "vulnerabilities"("id") ON DELETE CASCADE ON UPDATE CASCADE;
