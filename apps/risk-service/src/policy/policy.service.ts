import { BadRequestException, Injectable, NotFoundException } from '@nestjs/common';
import type { z } from 'zod';
import { PrismaService } from '@ctem/db';
import {
  CreatePolicyRequest,
  UpdatePolicyRequest,
  findTenantWebhookKeys,
} from '@ctem/contracts';

/**
 * Tenant-owned ordered notify rules. Evaluation stays in PolicyEngineService;
 * this is list / create / update against the existing Policy rows.
 *
 * Org is always the caller's principal. A miss (including RLS hide) is 404 —
 * never Prisma P2025 500, never empty 200 — so a cross-tenant GET cannot
 * confirm that the id exists.
 */
@Injectable()
export class PolicyService {
  constructor(private readonly prisma: PrismaService) {}

  list(orgId: string) {
    return this.prisma.withOrg(orgId, (tx) =>
      tx.policy.findMany({ orderBy: { priority: 'asc' } }),
    );
  }

  async get(orgId: string, id: string) {
    const policy = await this.prisma.withOrg(orgId, (tx) => tx.policy.findUnique({ where: { id } }));
    // RLS fail-closed looks the same as a missing row. Never 500 — that is how
    // a cross-tenant GET /v1/policies/:id would leak that the id exists (P2025).
    if (!policy) throw new NotFoundException(`Policy ${id} not found`);
    return policy;
  }

  async create(orgId: string, body: unknown) {
    const policy = this.parseWrite(CreatePolicyRequest, body);
    return this.prisma.withOrg(orgId, (tx) =>
      tx.policy.create({
        data: {
          orgId,
          name: policy.name,
          description: policy.description,
          enabled: policy.enabled,
          priority: policy.priority,
          condition: policy.condition as object,
          actions: policy.actions,
          slaHours: policy.slaHours,
        },
      }),
    );
  }

  async update(orgId: string, id: string, body: unknown) {
    const patch = this.parseWrite(UpdatePolicyRequest, body);
    return this.prisma.withOrg(orgId, async (tx) => {
      const existing = await tx.policy.findUnique({ where: { id } });
      // Same leak class as GET: miss → 404, never P2025 / empty 200.
      if (!existing) throw new NotFoundException(`Policy ${id} not found`);
      return tx.policy.update({
        where: { id },
        data: {
          ...(patch.name !== undefined ? { name: patch.name } : {}),
          ...(patch.description !== undefined ? { description: patch.description } : {}),
          ...(patch.enabled !== undefined ? { enabled: patch.enabled } : {}),
          ...(patch.priority !== undefined ? { priority: patch.priority } : {}),
          ...(patch.condition !== undefined ? { condition: patch.condition as object } : {}),
          ...(patch.actions !== undefined ? { actions: patch.actions } : {}),
          ...(patch.slaHours !== undefined ? { slaHours: patch.slaHours } : {}),
        },
      });
    });
  }

  private parseWrite<S extends z.ZodTypeAny>(schema: S, body: unknown): z.infer<S> {
    const webhookKeys = findTenantWebhookKeys(body);
    if (webhookKeys.length) {
      throw new BadRequestException(
        `tenant webhook URL is not allowed (${webhookKeys.join(', ')}) — Slack notify uses platform env:SLACK_* only`,
      );
    }
    const parsed = schema.safeParse(body);
    if (!parsed.success) {
      throw new BadRequestException({
        title: 'Validation failed',
        status: 400,
        errors: parsed.error.issues.map((issue) => ({
          path: issue.path.join('.'),
          message: issue.message,
          code: issue.code,
        })),
      });
    }
    return parsed.data;
  }
}
