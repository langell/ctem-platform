import { randomUUID } from 'node:crypto';
import {
  BadRequestException,
  ConflictException,
  Injectable,
  NotFoundException,
  ServiceUnavailableException,
} from '@nestjs/common';
import { PrismaService } from '@ctem/db';
import { loadEnv } from '@ctem/config';
import { ConnectGitHubRequest, IntegrationView } from '@ctem/contracts';
import { rootLogger } from '@ctem/observability';
import { CircuitOpenError } from '@ctem/resilience';
import { z } from 'zod';
import { DiscoverySchedulerService } from '../connectors/discovery-scheduler.service';
import { githubApiUrl } from '../connectors/github-api';
import { EGRESS_GITHUB_API, inventoryEgressFetch } from '../connectors/inventory-egress';
import { encryptIntegrationSecret } from '../secrets/credential-crypto';
import { toIntegrationView } from './integration-view';

const INVALID_TOKEN = 'Invalid GitHub token';
const OWNER_NOT_FOUND = 'GitHub owner not found';
const GITHUB_UNAVAILABLE = 'GitHub unavailable';
const NOT_FOUND = 'Integration not found';

/** Rows this slice created: a pasted GitHub token, not an env: platform credential. */
const PASTED_GITHUB = { provider: 'github', credentialRef: { startsWith: 'secret:' } } as const;

@Injectable()
export class IntegrationsService {
  private readonly log = rootLogger.child({ component: 'integrations' });

  constructor(
    private readonly prisma: PrismaService,
    private readonly discovery: DiscoverySchedulerService,
  ) {}

  async list(orgId: string): Promise<IntegrationView[]> {
    const rows = await this.prisma.withOrg(orgId, (tx) =>
      tx.integration.findMany({
        where: PASTED_GITHUB,
        include: { secret: true },
        orderBy: { createdAt: 'desc' },
      }),
    );
    return rows.map((row) => toIntegrationView(row));
  }

  async remove(orgId: string, id: string): Promise<void> {
    if (!z.string().uuid().safeParse(id).success) {
      throw new NotFoundException({ title: NOT_FOUND, status: 404 });
    }
    await this.prisma.withOrg(orgId, async (tx) => {
      await tx.integrationSecret.deleteMany({ where: { integrationId: id, orgId } });
      const deleted = await tx.integration.deleteMany({
        where: { id, orgId, ...PASTED_GITHUB },
      });
      if (deleted.count === 0) {
        throw new NotFoundException({ title: NOT_FOUND, status: 404 });
      }
    });
    this.log.info({ orgId, integrationId: id }, 'integration deleted');
  }

  async connectGitHub(orgId: string, body: ConnectGitHubRequest): Promise<IntegrationView> {
    if (
      body.owner.includes(body.token) ||
      (body.displayName !== undefined && body.displayName.includes(body.token))
    ) {
      this.log.warn(
        { reason: 'credential appeared in a non-secret field' },
        'github token validation rejected',
      );
      throw new BadRequestException({ title: INVALID_TOKEN, status: 400 });
    }

    const user = await this.githubFetch('/user', body.token);
    await user.body?.cancel().catch(() => undefined);
    this.assertStatus(user.status, 'token');

    if (body.ownerType === 'org') {
      const org = await this.githubFetch(`/orgs/${encodeURIComponent(body.owner)}`, body.token);
      await org.body?.cancel().catch(() => undefined);
      this.assertStatus(org.status, 'owner');
    }

    const id = randomUUID();
    const displayName = body.displayName ?? `github:${body.owner}`;
    let encrypted;
    try {
      encrypted = encryptIntegrationSecret(body.token, orgId, id);
    } catch {
      this.log.error({ orgId }, 'github credential encryption failed');
      throw new ServiceUnavailableException({
        title: 'GitHub credential could not be stored',
        status: 503,
      });
    }

    try {
      await this.prisma.withOrg(orgId, async (tx) => {
        await tx.integration.create({
          data: {
            id,
            orgId,
            provider: 'github',
            displayName,
            config: { owner: body.owner, ownerType: body.ownerType },
            credentialRef: `secret:${id}`,
            enabled: true,
          },
        });
        await tx.integrationSecret.create({
          data: {
            integrationId: id,
            orgId,
            ciphertext: Uint8Array.from(encrypted.ciphertext),
            iv: Uint8Array.from(encrypted.iv),
            authTag: Uint8Array.from(encrypted.authTag),
            keyId: encrypted.keyId,
          },
        });
      });
    } catch (err) {
      if (isUniqueViolation(err)) {
        throw new ConflictException({ title: 'GitHub integration already exists', status: 409 });
      }
      throw err;
    }

    const created = await this.prisma.withOrg(orgId, (tx) =>
      tx.integration.findUnique({ where: { id } }),
    );
    if (!created) {
      throw new NotFoundException({ title: 'Integration not found', status: 404 });
    }
    await this.discovery.syncIntegration(created);

    const synced = await this.prisma.withOrg(orgId, (tx) =>
      tx.integration.findUnique({ where: { id }, include: { secret: true } }),
    );
    if (!synced) {
      throw new NotFoundException({ title: 'Integration not found', status: 404 });
    }
    this.log.info({ orgId, integrationId: id, owner: body.owner }, 'github integration connected');
    return toIntegrationView(synced);
  }

  private async githubFetch(path: string, token: string): Promise<Response> {
    try {
      return await inventoryEgressFetch(EGRESS_GITHUB_API, githubApiUrl(path), {
        redirect: 'error',
        headers: {
          accept: 'application/vnd.github+json',
          'x-github-api-version': '2022-11-28',
          'user-agent': 'ctem-platform',
          authorization: `Bearer ${token}`,
        },
      });
    } catch (err) {
      if (err instanceof CircuitOpenError) {
        throw new ServiceUnavailableException({ title: GITHUB_UNAVAILABLE, status: 503 });
      }
      this.log.warn({ path }, 'github validation request failed');
      throw new ServiceUnavailableException({ title: GITHUB_UNAVAILABLE, status: 503 });
    }
  }

  private assertStatus(status: number, phase: 'token' | 'owner'): void {
    const githubApiOrigin = githubOrigin();
    if (status === 401 || status === 403) {
      this.log.warn(
        { phase, upstreamStatus: status, githubApiOrigin },
        'github token validation rejected',
      );
      throw new BadRequestException({ title: INVALID_TOKEN, status: 400 });
    }
    if (phase === 'owner' && status === 404) {
      this.log.warn(
        { phase, upstreamStatus: status, githubApiOrigin },
        'github owner validation rejected',
      );
      throw new BadRequestException({ title: OWNER_NOT_FOUND, status: 400 });
    }
    if (status < 200 || status >= 300) {
      throw new ServiceUnavailableException({ title: GITHUB_UNAVAILABLE, status: 503 });
    }
  }
}

function githubOrigin(): string {
  try {
    return new URL(loadEnv().GITHUB_API_URL).origin;
  } catch {
    return 'invalid';
  }
}

function isUniqueViolation(err: unknown): boolean {
  return (
    typeof err === 'object' &&
    err !== null &&
    'code' in err &&
    (err as { code: unknown }).code === 'P2002'
  );
}
