import { Injectable } from '@nestjs/common';
import { PrismaService } from '@ctem/db';
import { SEVERITY_ORDER, type RiskExplanation, type RiskWeights, type Severity } from '@ctem/contracts';

const DEFAULT_WEIGHTS: RiskWeights = {
  severity: 0.3,
  exploitability: 0.25,
  exposure: 0.25,
  businessCriticality: 0.2,
};

const EXPOSURE_SCORE: Record<string, number> = {
  internet_facing: 1,
  internal: 0.5,
  isolated: 0.15,
  unknown: 0.4,
};

const CRITICALITY_SCORE: Record<string, number> = {
  tier0: 1,
  tier1: 0.8,
  tier2: 0.5,
  tier3: 0.25,
  unknown: 0.4,
};

const VALIDATION_MULTIPLIER: Record<string, number> = {
  exploitable: 1.25,
  reachable: 1.1,
  not_validated: 1,
  compensating_control: 0.6,
  not_reachable: 0.4,
  not_exploitable: 0.3,
};

/**
 * Composite risk scoring. The point of this service is that a CVSS 9.8 in a
 * package nothing imports, on an isolated tier-3 asset, should rank below a
 * CVSS 6.5 that is internet-facing, on the KEV list and actually reachable.
 *
 * Every score is returned with its factors so the UI can show the arithmetic.
 * A score nobody can explain is a score nobody will act on.
 */
@Injectable()
export class RiskScoringService {
  constructor(private readonly prisma: PrismaService) {}

  async score(orgId: string, findingId: string): Promise<RiskExplanation> {
    const finding = await this.prisma.withOrg(orgId, (tx) =>
      tx.finding.findUniqueOrThrow({ where: { id: findingId }, include: { asset: true } }),
    );

    const weights = DEFAULT_WEIGHTS; // TODO: load per-org overrides from policy

    const severityRaw = SEVERITY_ORDER[finding.severity as Severity] / 5;
    // EPSS is the probability of exploitation in the next 30 days; KEV means it
    // is already happening. KEV therefore floors exploitability at 0.9.
    const exploitRaw = finding.kev ? Math.max(0.9, finding.epssScore ?? 0) : (finding.epssScore ?? 0.05);
    const exposureRaw = EXPOSURE_SCORE[finding.asset.exposure] ?? 0.4;
    const criticalityRaw = CRITICALITY_SCORE[finding.asset.criticality] ?? 0.4;

    const factors = [
      {
        name: 'severity',
        weight: weights.severity,
        rawValue: severityRaw,
        contribution: severityRaw * weights.severity,
        note: `${finding.severity}${finding.cvssScore ? ` (CVSS ${finding.cvssScore})` : ''}`,
      },
      {
        name: 'exploitability',
        weight: weights.exploitability,
        rawValue: exploitRaw,
        contribution: exploitRaw * weights.exploitability,
        note: finding.kev ? 'on CISA KEV' : `EPSS ${((finding.epssScore ?? 0) * 100).toFixed(1)}%`,
      },
      {
        name: 'exposure',
        weight: weights.exposure,
        rawValue: exposureRaw,
        contribution: exposureRaw * weights.exposure,
        note: finding.asset.exposure,
      },
      {
        name: 'businessCriticality',
        weight: weights.businessCriticality,
        rawValue: criticalityRaw,
        contribution: criticalityRaw * weights.businessCriticality,
        note: finding.asset.criticality,
      },
    ];

    const base = factors.reduce((sum, f) => sum + f.contribution, 0);
    const multiplier = VALIDATION_MULTIPLIER[finding.validation] ?? 1;
    const score = Math.round(Math.min(100, base * multiplier * 100));

    if (multiplier !== 1) {
      factors.push({
        name: 'validation',
        weight: 0,
        rawValue: multiplier,
        contribution: base * (multiplier - 1),
        note: finding.validation,
      });
    }

    await this.prisma.withOrg(orgId, (tx) =>
      tx.finding.update({ where: { id: findingId }, data: { riskScore: score } }),
    );

    return { findingId, score, factors, matchedPolicies: [] };
  }

  /** Batch rescore — used after a feed update changes EPSS/KEV for many CVEs. */
  async rescoreAll(orgId: string, findingIds?: string[]): Promise<number> {
    const targets = await this.prisma.withOrg(orgId, (tx) =>
      tx.finding.findMany({
        where: {
          state: { in: ['open', 'triaged', 'in_progress'] },
          ...(findingIds?.length ? { id: { in: findingIds } } : {}),
        },
        select: { id: true },
      }),
    );

    for (const { id } of targets) {
      await this.score(orgId, id);
    }
    return targets.length;
  }
}
