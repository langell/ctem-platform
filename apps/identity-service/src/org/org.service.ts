import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from '@ctem/db';
import { Role } from '@ctem/contracts';

@Injectable()
export class OrgService {
  constructor(private readonly prisma: PrismaService) {}

  /** Org creation is the one legitimately cross-tenant write in the system. */
  async createOrg(name: string, slug: string, ownerUserId: string) {
    return this.prisma.unsafeCrossTenant('org bootstrap has no tenant context yet', async (db) =>
      db.organization.create({
        data: {
          name,
          slug,
          memberships: { create: { userId: ownerUserId, role: 'owner' } },
          policies: {
            // Sensible defaults so a new org is not staring at an empty policy list.
            create: [
              {
                name: 'Internet-facing critical',
                description: 'Anything critical and reachable from the internet is a page.',
                priority: 10,
                condition: { severityAtLeast: 'critical', exposure: ['internet_facing'] },
                actions: ['notify', 'ticket', 'block_deploy'],
                slaHours: 24,
              },
              {
                name: 'Known exploited vulnerabilities',
                description: 'On the CISA KEV list — fix within a week regardless of CVSS.',
                priority: 20,
                condition: { kevOnly: true },
                actions: ['notify', 'ticket'],
                slaHours: 168,
              },
              {
                name: 'High severity with a fix',
                description: 'Fail the build only when the team can actually act.',
                priority: 50,
                condition: { severityAtLeast: 'high', requireFixAvailable: true },
                actions: ['ticket', 'fail_build'],
                slaHours: 336,
              },
            ],
          },
        },
      }),
    );
  }

  async members(orgId: string) {
    return this.prisma.withOrg(orgId, (tx) =>
      tx.membership.findMany({ include: { user: true } }),
    );
  }

  async setRole(orgId: string, actorRole: Role, userId: string, role: Role) {
    // Only an owner can mint another owner — otherwise privilege escalation is
    // one PATCH away.
    if (role === 'owner' && actorRole !== 'owner') {
      throw new ForbiddenException('Only an owner can grant ownership');
    }
    return this.prisma.withOrg(orgId, (tx) =>
      tx.membership.update({ where: { orgId_userId: { orgId, userId } }, data: { role } }),
    );
  }
}
