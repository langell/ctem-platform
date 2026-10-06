-- One active self-signup membership per user. viaSignup stays false for
-- invites and for every membership this migration backfills, so existing
-- rows are not in the index. Disabling a signup membership (disabledAt)
-- releases the key and allows a replacement org.

ALTER TABLE "memberships" ADD COLUMN "viaSignup" BOOLEAN NOT NULL DEFAULT false;

CREATE UNIQUE INDEX "memberships_userId_signup_active_key"
ON "memberships"("userId")
WHERE "viaSignup" AND "disabledAt" IS NULL;
