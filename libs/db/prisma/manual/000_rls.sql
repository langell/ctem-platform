-- Row-level security for multi-tenant isolation.
--
-- Run this AFTER the generated Prisma migration that creates the tables.
-- The application connects as `ctem_app`, which is NOT the table owner and has
-- no BYPASSRLS, so every statement is filtered by the policies below. The org
-- is set per transaction via `SET LOCAL app.current_org_id = '<uuid>'`.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ctem_app') THEN
    CREATE ROLE ctem_app LOGIN PASSWORD 'ctem_app';
  END IF;
END
$$;

GRANT USAGE ON SCHEMA public TO ctem_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ctem_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO ctem_app;

-- Returns NULL when unset, which makes every policy fail closed.
CREATE OR REPLACE FUNCTION current_org_id() RETURNS uuid
LANGUAGE sql STABLE AS $$
  SELECT NULLIF(current_setting('app.current_org_id', true), '')::uuid;
$$;

DO $$
DECLARE
  t text;
  tenant_tables text[] := ARRAY[
    'assets', 'asset_edges', 'integrations', 'scans', 'scan_jobs',
    'findings', 'finding_events', 'sbom_components', 'policies',
    'risk_exceptions', 'audit_logs', 'api_tokens', 'memberships'
  ];
BEGIN
  FOREACH t IN ARRAY tenant_tables LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON %I
         USING ("orgId" = current_org_id())
         WITH CHECK ("orgId" = current_org_id())', t);
  END LOOP;
END
$$;

-- Organizations: a member can only see their own org row.
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON organizations;
CREATE POLICY tenant_isolation ON organizations
  USING (id = current_org_id())
  WITH CHECK (id = current_org_id());

-- Vulnerability intelligence is shared reference data: readable by all, written
-- only by the feed ingester running under the owner role.
REVOKE INSERT, UPDATE, DELETE ON vulnerabilities FROM ctem_app;
REVOKE INSERT, UPDATE, DELETE ON vulnerability_affects FROM ctem_app;
REVOKE INSERT, UPDATE, DELETE ON vuln_package_sync FROM ctem_app;

-- PAT verification has to find a token by hash before any org context exists,
-- but api_tokens is policy-protected and fails closed. The lookup therefore
-- goes through a SECURITY DEFINER function owned by the migration role, which
-- exposes exactly one query shape (hash equality) to ctem_app and nothing else.
-- NOTE: in environments where the migration role is not a superuser, it must
-- be granted BYPASSRLS for this function to see across tenants.
CREATE OR REPLACE FUNCTION verify_api_token(p_hash text)
RETURNS SETOF api_tokens
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public
AS $$
  SELECT * FROM api_tokens WHERE "tokenHash" = p_hash;
$$;

REVOKE ALL ON FUNCTION verify_api_token(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION verify_api_token(text) TO ctem_app;
