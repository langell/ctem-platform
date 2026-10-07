-- Read-only pre-check for memberships_userId_active_key.
--
-- Run this before `make db-migrate`. That target uses `prisma migrate dev`,
-- which can offer to reset the database. This script only SELECTs.
--
-- The migration raises and stops when any user has two or more active
-- memberships (disabledAt IS NULL). It never auto-disables rows.
--
-- Manual fix when this query returns rows, or when the migration fails:
-- 1. Decide which org the user keeps.
-- 2. UPDATE memberships SET "disabledAt" = now()
--      WHERE "userId" = '…' AND "orgId" = '…';
--    for every other active membership (usually the newer one).
-- 3. pnpm prisma migrate resolve --rolled-back 20261007124500_membership_one_active --schema libs/db/prisma/schema.prisma
--    then pnpm db:deploy

SELECT m."userId", u.email, count(*) AS active_count,
       array_agg(m."orgId" ORDER BY m."createdAt") AS org_ids,
       array_agg(m."createdAt" ORDER BY m."createdAt") AS created_at
FROM memberships m JOIN users u ON u.id = m."userId"
WHERE m."disabledAt" IS NULL
GROUP BY m."userId", u.email HAVING count(*) > 1 ORDER BY active_count DESC;
