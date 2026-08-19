import { Injectable, UnauthorizedException } from '@nestjs/common';
import { createHash, randomBytes } from 'node:crypto';
import { PrismaService } from '@ctem/db';

const PREFIX = 'ctem_pat_';

/**
 * Machine tokens for CI and connectors. The plaintext is shown exactly once;
 * only a SHA-256 hash is stored, so a database dump does not hand over API access.
 */
@Injectable()
export class ApiTokenService {
  constructor(private readonly prisma: PrismaService) {}

  async issue(orgId: string, name: string, scopes: string[], expiresAt?: Date) {
    const secret = `${PREFIX}${randomBytes(32).toString('base64url')}`;
    const record = await this.prisma.withOrg(orgId, (tx) =>
      tx.apiToken.create({
        data: { orgId, name, scopes, tokenHash: this.hash(secret), expiresAt },
      }),
    );
    return { id: record.id, name: record.name, token: secret, expiresAt: record.expiresAt };
  }

  async verify(presented: string) {
    if (!presented.startsWith(PREFIX)) throw new UnauthorizedException('Malformed token');

    const token = await this.prisma.unsafeCrossTenant('token lookup precedes tenant context', (db) =>
      db.apiToken.findUnique({ where: { tokenHash: this.hash(presented) } }),
    );

    if (!token || token.revokedAt) throw new UnauthorizedException('Invalid token');
    if (token.expiresAt && token.expiresAt < new Date()) throw new UnauthorizedException('Token expired');

    // Best-effort; a failed lastUsedAt write must not fail the request.
    void this.prisma
      .withOrg(token.orgId, (tx) =>
        tx.apiToken.update({ where: { id: token.id }, data: { lastUsedAt: new Date() } }),
      )
      .catch(() => undefined);

    return { orgId: token.orgId, tokenId: token.id, scopes: token.scopes, name: token.name };
  }

  async revoke(orgId: string, id: string) {
    return this.prisma.withOrg(orgId, (tx) =>
      tx.apiToken.update({ where: { id }, data: { revokedAt: new Date() } }),
    );
  }

  private hash(token: string): string {
    return createHash('sha256').update(token).digest('hex');
  }
}
