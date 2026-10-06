import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { CREDENTIAL_KEY_ID, decodeCredentialEncryptionKey, loadEnv } from '@ctem/config';

const FIXED_DECRYPT_ERROR = 'GitHub credential could not be decrypted';

export interface EncryptedCredential {
  ciphertext: Buffer;
  iv: Buffer;
  authTag: Buffer;
  keyId: string;
}

export function credentialAad(orgId: string, integrationId: string): Buffer {
  return Buffer.from(`${orgId}:${integrationId}`, 'utf8');
}

function encryptionKey(): Buffer {
  const key = decodeCredentialEncryptionKey(loadEnv().CREDENTIAL_ENCRYPTION_KEY);
  if (!key) {
    throw new Error('CREDENTIAL_ENCRYPTION_KEY is not configured');
  }
  return key;
}

export function encryptIntegrationSecret(
  plaintext: string,
  orgId: string,
  integrationId: string,
): EncryptedCredential {
  const key = encryptionKey();
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(credentialAad(orgId, integrationId));
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return { ciphertext, iv, authTag: cipher.getAuthTag(), keyId: CREDENTIAL_KEY_ID };
}

export function decryptIntegrationSecret(
  row: EncryptedCredential,
  orgId: string,
  integrationId: string,
): string {
  if (row.keyId !== CREDENTIAL_KEY_ID) {
    throw new Error(FIXED_DECRYPT_ERROR);
  }
  try {
    const decipher = createDecipheriv('aes-256-gcm', encryptionKey(), row.iv);
    decipher.setAAD(credentialAad(orgId, integrationId));
    decipher.setAuthTag(row.authTag);
    const plain = Buffer.concat([decipher.update(row.ciphertext), decipher.final()]);
    return plain.toString('utf8');
  } catch (err) {
    if (err instanceof Error && err.message === 'CREDENTIAL_ENCRYPTION_KEY is not configured') {
      throw err;
    }
    throw new Error(FIXED_DECRYPT_ERROR);
  }
}
