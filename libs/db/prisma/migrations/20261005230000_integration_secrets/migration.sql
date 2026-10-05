-- Per-tenant integration credentials. Ciphertext only.
-- RLS matches the other tenant tables. current_org_id() is also created by
-- manual/000_rls.sql, which re-applies this policy after grants.

CREATE OR REPLACE FUNCTION current_org_id() RETURNS uuid
LANGUAGE sql STABLE AS $$
  SELECT NULLIF(current_setting('app.current_org_id', true), '')::uuid;
$$;

CREATE TABLE "integration_secrets" (
    "integrationId" UUID NOT NULL,
    "orgId" UUID NOT NULL,
    "ciphertext" BYTEA NOT NULL,
    "iv" BYTEA NOT NULL,
    "authTag" BYTEA NOT NULL,
    "keyId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "integration_secrets_pkey" PRIMARY KEY ("integrationId")
);

CREATE INDEX "integration_secrets_orgId_idx" ON "integration_secrets"("orgId");

ALTER TABLE "integration_secrets" ADD CONSTRAINT "integration_secrets_integrationId_fkey" FOREIGN KEY ("integrationId") REFERENCES "integrations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "integration_secrets" ADD CONSTRAINT "integration_secrets_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "integration_secrets" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "integration_secrets" FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON "integration_secrets";
CREATE POLICY tenant_isolation ON "integration_secrets"
  USING ("orgId" = current_org_id())
  WITH CHECK ("orgId" = current_org_id());
