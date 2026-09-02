import { Injectable } from '@nestjs/common';
import { PrismaService } from '@ctem/db';
import { EventBus } from '@ctem/events';
import { SUBJECTS, type PolicyCondition, matchesPolicyCondition } from '@ctem/contracts';
import { rootLogger } from '@ctem/observability';
import {
  SEED_KEV_OR_CRITICAL_POLICY_ID,
  SEED_NOTIFY_ACTIONS,
  matchesSeedKevOrCritical,
} from './seed-notify';

interface EvaluableFinding {
  id: string;
  severity: string;
  riskScore: number;
  kev: boolean;
  epssScore: number | null;
  fixAvailable: boolean;
  scannerType: string;
  asset: { kind: string; exposure: string; criticality: string; tags: unknown };
}

/**
 * Policies decide what happens to a finding: notify, ticket, break the build,
 * block the deploy. Rules are ordered by priority and the first match wins, so
 * an org can write a broad default and narrow exceptions above it.
 */
@Injectable()
export class PolicyEngineService {
  private readonly log = rootLogger.child({ component: 'policy-engine' });

  constructor(
    private readonly prisma: PrismaService,
    private readonly bus: EventBus,
  ) {}

  async evaluate(orgId: string, findingId: string): Promise<string[]> {
    const finding = (await this.prisma.withOrg(orgId, (tx) =>
      tx.finding.findUniqueOrThrow({ where: { id: findingId }, include: { asset: true } }),
    )) as unknown as EvaluableFinding;

    // An active, approved exception short-circuits everything below it.
    if (await this.hasActiveException(orgId, finding)) {
      this.log.debug({ findingId }, 'suppressed by risk exception');
      return [];
    }

    const policies = await this.prisma.withOrg(orgId, (tx) =>
      tx.policy.findMany({ where: { enabled: true }, orderBy: { priority: 'asc' } }),
    );

    for (const policy of policies) {
      if (!this.matches(policy.condition as PolicyCondition, finding)) continue;

      if (policy.slaHours) {
        await this.prisma.withOrg(orgId, (tx) =>
          tx.finding.update({
            where: { id: findingId },
            data: { slaDueAt: new Date(Date.now() + policy.slaHours! * 3_600_000) },
          }),
        );
      }

      await this.bus.publish(SUBJECTS.policyViolated, orgId, {
        findingId,
        policyId: policy.id,
        actions: policy.actions,
      });

      this.log.info({ findingId, policyId: policy.id, actions: policy.actions }, 'policy matched');
      return policy.actions;
    }

    // Seed rule, not a policy editor: KEV or critical → notify when no tenant
    // policy matched, so `ctem.policy.violated` actually emits.
    if (matchesSeedKevOrCritical(finding)) {
      const actions = [...SEED_NOTIFY_ACTIONS];
      await this.bus.publish(SUBJECTS.policyViolated, orgId, {
        findingId,
        policyId: SEED_KEV_OR_CRITICAL_POLICY_ID,
        actions,
      });
      this.log.info(
        { findingId, policyId: SEED_KEV_OR_CRITICAL_POLICY_ID, actions },
        'seed KEV-or-critical policy matched',
      );
      return actions;
    }

    return [];
  }

  private matches(condition: PolicyCondition, finding: EvaluableFinding): boolean {
    return matchesPolicyCondition(condition, finding);
  }

  private async hasActiveException(orgId: string, finding: EvaluableFinding): Promise<boolean> {
    const now = new Date();
    const count = await this.prisma.withOrg(orgId, (tx) =>
      tx.riskException.count({
        where: {
          revokedAt: null,
          approvedAt: { not: null },
          expiresAt: { gt: now },
          OR: [
            { scope: 'finding', targetRef: finding.id },
            { scope: 'global' },
          ],
        },
      }),
    );
    return count > 0;
  }
}
