-- One active membership per user (disabledAt IS NULL), whatever its provenance.
-- The guard runs before any DDL. It never disables a row. Fix duplicates by
-- hand with tools/db/one-active-precheck.sql, then re-run.
-- viaSignup stays as provenance; the signup partial index is superseded
-- because every row it covered is covered by the new index.

-- guard:begin
DO $$
DECLARE
  n integer;
BEGIN
  SELECT count(*)::integer INTO n
  FROM (
    SELECT "userId"
    FROM memberships
    WHERE "disabledAt" IS NULL
    GROUP BY "userId"
    HAVING count(*) > 1
  ) AS dupes;
  IF n > 0 THEN
    RAISE EXCEPTION 'ctem: % user(s) have 2+ active memberships; cannot create memberships_userId_active_key. Run tools/db/one-active-precheck.sql, keep one org per user, disable the others by hand, then re-run.', n;
  END IF;
END
$$;
-- guard:end

DROP INDEX IF EXISTS "memberships_userId_signup_active_key";

CREATE UNIQUE INDEX "memberships_userId_active_key"
ON "memberships"("userId")
WHERE "disabledAt" IS NULL;

CREATE INDEX "membership_invites_email_pending_idx"
ON "membership_invites"("email")
WHERE "acceptedAt" IS NULL;
