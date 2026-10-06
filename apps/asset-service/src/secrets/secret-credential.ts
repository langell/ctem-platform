import type { PrismaService } from '@ctem/db';
import { parseSecretCredentialRef } from '../connectors/credentials';
import { decryptIntegrationSecret } from './credential-crypto';

const FIXED = 'GitHub credential could not be decrypted';

/**
 * Decrypt a secret: ref inside the integration's org. The connector never
 * calls this. A missing row, a mismatched id, or an AAD failure throws a
 * fixed message so the scheduler records a sync error and does not archive.
 */
export async function loadSecretCredential(
  prisma: PrismaService,
  integration: { id: string; orgId: string; credentialRef: string | null },
): Promise<string> {
  const secretId = parseSecretCredentialRef(integration.credentialRef);
  if (!secretId || secretId !== integration.id) {
    throw new Error(FIXED);
  }
  const row = await prisma.withOrg(integration.orgId, (tx) =>
    tx.integrationSecret.findUnique({ where: { integrationId: integration.id } }),
  );
  if (!row || row.orgId !== integration.orgId) {
    throw new Error(FIXED);
  }
  return decryptIntegrationSecret(
    {
      ciphertext: Buffer.from(row.ciphertext),
      iv: Buffer.from(row.iv),
      authTag: Buffer.from(row.authTag),
      keyId: row.keyId,
    },
    integration.orgId,
    integration.id,
  );
}
