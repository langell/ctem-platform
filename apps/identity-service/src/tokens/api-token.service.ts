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

    // The lookup happens before any org context exists, and RLS fails closed —
    // a plain findUnique returns nothing under the ctem_app role. It goes
    // through the SECURITY DEFINER function from 000_rls.sql instead.
    const rows = await this.prisma.$queryRaw<
      {
        id: string;
        orgId: string;
        name: string;
        scopes: string[];
        revokedAt: Date | null;
        expiresAt: Date | null;
      }[]
    >`SELECT * FROM verify_api_token(${this.hash(presented)})`;
    const token = rows[0];

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
