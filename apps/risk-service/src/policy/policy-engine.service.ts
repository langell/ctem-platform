import { Injectable } from '@nestjs/common';
import { PrismaService } from '@ctem/db';
import { EventBus } from '@ctem/events';
import { SEVERITY_ORDER, SUBJECTS, type PolicyCondition, type Severity } from '@ctem/contracts';
import { rootLogger } from '@ctem/observability';

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

    return [];
  }

  private matches(condition: PolicyCondition, finding: EvaluableFinding): boolean {
    if (
      condition.severityAtLeast &&
      SEVERITY_ORDER[finding.severity as Severity] < SEVERITY_ORDER[condition.severityAtLeast]
    ) {
      return false;
    }
    if (condition.minRiskScore !== undefined && finding.riskScore < condition.minRiskScore) return false;
    if (condition.kevOnly && !finding.kev) return false;
    if (condition.minEpss !== undefined && (finding.epssScore ?? 0) < condition.minEpss) return false;
    // "Only fail the build for things the team can actually fix" is the single
    // most requested policy knob in every tool of this class.
    if (condition.requireFixAvailable && !finding.fixAvailable) return false;
    if (condition.scannerTypes?.length && !condition.scannerTypes.includes(finding.scannerType)) return false;
    if (condition.assetKinds?.length && !condition.assetKinds.includes(finding.asset.kind)) return false;
    if (condition.exposure?.length && !condition.exposure.includes(finding.asset.exposure)) return false;
    if (condition.criticality?.length && !condition.criticality.includes(finding.asset.criticality)) return false;

    if (condition.assetTags) {
      const tags = (finding.asset.tags ?? {}) as Record<string, string>;
      for (const [k, v] of Object.entries(condition.assetTags)) {
        if (tags[k] !== v) return false;
      }
    }
    return true;
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
