-- Durable SLA breach notify-once claim. Null means this finding has not yet
-- published ctem.policy.sla_breached for the current SLA window.
-- AlterTable
ALTER TABLE "findings" ADD COLUMN "slaNotifiedAt" TIMESTAMP(3);
