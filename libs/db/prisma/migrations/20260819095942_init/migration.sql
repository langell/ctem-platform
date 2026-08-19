-- CreateTable
CREATE TABLE "organizations" (
    "id" UUID NOT NULL,
    "name" TEXT NOT NULL,
    "slug" TEXT NOT NULL,
    "plan" TEXT NOT NULL DEFAULT 'trial',
    "dataResidency" TEXT NOT NULL DEFAULT 'us',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "organizations_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "users" (
    "id" UUID NOT NULL,
    "email" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "idpSubject" TEXT NOT NULL,
    "disabledAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "users_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "memberships" (
    "orgId" UUID NOT NULL,
    "userId" UUID NOT NULL,
    "role" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "memberships_pkey" PRIMARY KEY ("orgId","userId")
);

-- CreateTable
CREATE TABLE "api_tokens" (
    "id" UUID NOT NULL,
    "orgId" UUID NOT NULL,
    "name" TEXT NOT NULL,
    "tokenHash" TEXT NOT NULL,
    "scopes" TEXT[],
    "lastUsedAt" TIMESTAMP(3),
    "expiresAt" TIMESTAMP(3),
    "revokedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "api_tokens_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "assets" (
    "id" UUID NOT NULL,
    "orgId" UUID NOT NULL,
    "kind" TEXT NOT NULL,
    "externalKey" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "exposure" TEXT NOT NULL DEFAULT 'unknown',
    "criticality" TEXT NOT NULL DEFAULT 'unknown',
    "dataClasses" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "ownerTeam" TEXT,
    "ownerEmail" TEXT,
    "tags" JSONB NOT NULL DEFAULT '{}',
    "attributes" JSONB NOT NULL DEFAULT '{}',
    "firstSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "archivedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "assets_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "asset_edges" (
    "id" UUID NOT NULL,
    "orgId" UUID NOT NULL,
    "fromAssetId" UUID NOT NULL,
    "toAssetId" UUID NOT NULL,
    "kind" TEXT NOT NULL,
    "confidence" DOUBLE PRECISION NOT NULL DEFAULT 1,

    CONSTRAINT "asset_edges_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "integrations" (
    "id" UUID NOT NULL,
    "orgId" UUID NOT NULL,
    "provider" TEXT NOT NULL,
    "displayName" TEXT NOT NULL,
    "config" JSONB NOT NULL DEFAULT '{}',
    "credentialRef" TEXT,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "lastSyncAt" TIMESTAMP(3),
    "lastSyncError" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "integrations_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "scans" (
    "id" UUID NOT NULL,
    "orgId" UUID NOT NULL,
    "scannerType" TEXT NOT NULL,
    "trigger" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'queued',
    "requestedBy" UUID,
    "assetSelector" JSONB NOT NULL DEFAULT '{}',
    "options" JSONB NOT NULL DEFAULT '{}',
    "jobsTotal" INTEGER NOT NULL DEFAULT 0,
    "jobsCompleted" INTEGER NOT NULL DEFAULT 0,
    "startedAt" TIMESTAMP(3),
    "finishedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "scans_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "scan_jobs" (
    "id" UUID NOT NULL,
    "orgId" UUID NOT NULL,
    "scanId" UUID NOT NULL,
    "assetId" UUID NOT NULL,
    "scannerType" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'queued',
    "attempt" INTEGER NOT NULL DEFAULT 1,
    "artifactKey" TEXT,
    "findingCount" INTEGER NOT NULL DEFAULT 0,
    "error" TEXT,
    "stats" JSONB NOT NULL DEFAULT '{}',
    "startedAt" TIMESTAMP(3),
    "finishedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "scan_jobs_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "findings" (
    "id" UUID NOT NULL,
    "orgId" UUID NOT NULL,
    "assetId" UUID NOT NULL,
    "fingerprint" TEXT NOT NULL,
    "scannerType" TEXT NOT NULL,
    "scannerName" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "description" TEXT NOT NULL DEFAULT '',
    "severity" TEXT NOT NULL,
    "riskScore" DOUBLE PRECISION NOT NULL DEFAULT 0,
    "state" TEXT NOT NULL DEFAULT 'open',
    "validation" TEXT NOT NULL DEFAULT 'not_validated',
    "identifiers" JSONB NOT NULL DEFAULT '[]',
    "cvssScore" DOUBLE PRECISION,
    "cvssVector" TEXT,
    "epssScore" DOUBLE PRECISION,
    "kev" BOOLEAN NOT NULL DEFAULT false,
    "location" JSONB NOT NULL DEFAULT '{}',
    "evidence" JSONB NOT NULL DEFAULT '{}',
    "fixAvailable" BOOLEAN NOT NULL DEFAULT false,
    "fixedVersion" TEXT,
    "artifactKey" TEXT,
    "slaDueAt" TIMESTAMP(3),
    "ticketRef" TEXT,
    "firstSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "resolvedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "findings_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "finding_events" (
    "id" UUID NOT NULL,
    "orgId" UUID NOT NULL,
    "findingId" UUID NOT NULL,
    "type" TEXT NOT NULL,
    "fromState" TEXT,
    "toState" TEXT,
    "actor" TEXT NOT NULL,
    "reason" TEXT,
    "metadata" JSONB NOT NULL DEFAULT '{}',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "finding_events_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sbom_components" (
    "id" UUID NOT NULL,
    "orgId" UUID NOT NULL,
    "assetId" UUID NOT NULL,
    "purl" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "version" TEXT NOT NULL,
    "ecosystem" TEXT NOT NULL,
    "direct" BOOLEAN NOT NULL DEFAULT false,
    "dependencyPath" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "licenses" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "sbom_components_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "vulnerabilities" (
    "id" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "aliases" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "summary" TEXT NOT NULL DEFAULT '',
    "details" TEXT NOT NULL DEFAULT '',
    "severity" TEXT NOT NULL DEFAULT 'unknown',
    "cvssVector" TEXT,
    "cvssScore" DOUBLE PRECISION,
    "epssScore" DOUBLE PRECISION,
    "epssPercentile" DOUBLE PRECISION,
    "kev" BOOLEAN NOT NULL DEFAULT false,
    "kevDueDate" TIMESTAMP(3),
    "publishedAt" TIMESTAMP(3),
    "modifiedAt" TIMESTAMP(3),
    "references" JSONB NOT NULL DEFAULT '[]',
    "affected" JSONB NOT NULL DEFAULT '[]',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "vulnerabilities_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "policies" (
    "id" UUID NOT NULL,
    "orgId" UUID NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT NOT NULL DEFAULT '',
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "priority" INTEGER NOT NULL DEFAULT 100,
    "condition" JSONB NOT NULL,
    "actions" TEXT[],
    "slaHours" INTEGER,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "policies_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "risk_exceptions" (
    "id" UUID NOT NULL,
    "orgId" UUID NOT NULL,
    "scope" TEXT NOT NULL,
    "targetRef" TEXT NOT NULL,
    "reason" TEXT NOT NULL,
    "requestedBy" UUID NOT NULL,
    "approvedBy" UUID,
    "approvedAt" TIMESTAMP(3),
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "revokedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "risk_exceptions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "audit_logs" (
    "id" UUID NOT NULL,
    "orgId" UUID NOT NULL,
    "actor" TEXT NOT NULL,
    "action" TEXT NOT NULL,
    "resource" TEXT NOT NULL,
    "resourceId" TEXT,
    "metadata" JSONB NOT NULL DEFAULT '{}',
    "ip" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "audit_logs_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "organizations_slug_key" ON "organizations"("slug");

-- CreateIndex
CREATE UNIQUE INDEX "users_email_key" ON "users"("email");

-- CreateIndex
CREATE UNIQUE INDEX "users_idpSubject_key" ON "users"("idpSubject");

-- CreateIndex
CREATE INDEX "memberships_userId_idx" ON "memberships"("userId");

-- CreateIndex
CREATE UNIQUE INDEX "api_tokens_tokenHash_key" ON "api_tokens"("tokenHash");

-- CreateIndex
CREATE INDEX "api_tokens_orgId_idx" ON "api_tokens"("orgId");

-- CreateIndex
CREATE INDEX "assets_orgId_kind_idx" ON "assets"("orgId", "kind");

-- CreateIndex
CREATE INDEX "assets_orgId_exposure_criticality_idx" ON "assets"("orgId", "exposure", "criticality");

-- CreateIndex
CREATE UNIQUE INDEX "assets_orgId_externalKey_key" ON "assets"("orgId", "externalKey");

-- CreateIndex
CREATE INDEX "asset_edges_orgId_toAssetId_idx" ON "asset_edges"("orgId", "toAssetId");

-- CreateIndex
CREATE UNIQUE INDEX "asset_edges_orgId_fromAssetId_toAssetId_kind_key" ON "asset_edges"("orgId", "fromAssetId", "toAssetId", "kind");

-- CreateIndex
CREATE UNIQUE INDEX "integrations_orgId_provider_displayName_key" ON "integrations"("orgId", "provider", "displayName");

-- CreateIndex
CREATE INDEX "scans_orgId_scannerType_createdAt_idx" ON "scans"("orgId", "scannerType", "createdAt");

-- CreateIndex
CREATE INDEX "scan_jobs_orgId_status_idx" ON "scan_jobs"("orgId", "status");

-- CreateIndex
CREATE INDEX "scan_jobs_scanId_idx" ON "scan_jobs"("scanId");

-- CreateIndex
CREATE INDEX "findings_orgId_state_severity_idx" ON "findings"("orgId", "state", "severity");

-- CreateIndex
CREATE INDEX "findings_orgId_riskScore_idx" ON "findings"("orgId", "riskScore" DESC);

-- CreateIndex
CREATE INDEX "findings_orgId_slaDueAt_idx" ON "findings"("orgId", "slaDueAt");

-- CreateIndex
CREATE INDEX "findings_assetId_idx" ON "findings"("assetId");

-- CreateIndex
CREATE UNIQUE INDEX "findings_orgId_fingerprint_key" ON "findings"("orgId", "fingerprint");

-- CreateIndex
CREATE INDEX "finding_events_findingId_createdAt_idx" ON "finding_events"("findingId", "createdAt");

-- CreateIndex
CREATE INDEX "sbom_components_orgId_name_version_idx" ON "sbom_components"("orgId", "name", "version");

-- CreateIndex
CREATE UNIQUE INDEX "sbom_components_orgId_assetId_purl_key" ON "sbom_components"("orgId", "assetId", "purl");

-- CreateIndex
CREATE INDEX "vulnerabilities_kev_idx" ON "vulnerabilities"("kev");

-- CreateIndex
CREATE INDEX "vulnerabilities_epssScore_idx" ON "vulnerabilities"("epssScore" DESC);

-- CreateIndex
CREATE INDEX "policies_orgId_enabled_priority_idx" ON "policies"("orgId", "enabled", "priority");

-- CreateIndex
CREATE UNIQUE INDEX "policies_orgId_name_key" ON "policies"("orgId", "name");

-- CreateIndex
CREATE INDEX "risk_exceptions_orgId_scope_targetRef_idx" ON "risk_exceptions"("orgId", "scope", "targetRef");

-- CreateIndex
CREATE INDEX "risk_exceptions_orgId_expiresAt_idx" ON "risk_exceptions"("orgId", "expiresAt");

-- CreateIndex
CREATE INDEX "audit_logs_orgId_createdAt_idx" ON "audit_logs"("orgId", "createdAt");

-- AddForeignKey
ALTER TABLE "memberships" ADD CONSTRAINT "memberships_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "memberships" ADD CONSTRAINT "memberships_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "api_tokens" ADD CONSTRAINT "api_tokens_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "assets" ADD CONSTRAINT "assets_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "asset_edges" ADD CONSTRAINT "asset_edges_fromAssetId_fkey" FOREIGN KEY ("fromAssetId") REFERENCES "assets"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "asset_edges" ADD CONSTRAINT "asset_edges_toAssetId_fkey" FOREIGN KEY ("toAssetId") REFERENCES "assets"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "integrations" ADD CONSTRAINT "integrations_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "scans" ADD CONSTRAINT "scans_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "scan_jobs" ADD CONSTRAINT "scan_jobs_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "scans"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "scan_jobs" ADD CONSTRAINT "scan_jobs_assetId_fkey" FOREIGN KEY ("assetId") REFERENCES "assets"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "findings" ADD CONSTRAINT "findings_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "findings" ADD CONSTRAINT "findings_assetId_fkey" FOREIGN KEY ("assetId") REFERENCES "assets"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "finding_events" ADD CONSTRAINT "finding_events_findingId_fkey" FOREIGN KEY ("findingId") REFERENCES "findings"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "sbom_components" ADD CONSTRAINT "sbom_components_assetId_fkey" FOREIGN KEY ("assetId") REFERENCES "assets"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "policies" ADD CONSTRAINT "policies_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "risk_exceptions" ADD CONSTRAINT "risk_exceptions_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "audit_logs" ADD CONSTRAINT "audit_logs_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;
