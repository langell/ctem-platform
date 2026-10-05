import { afterEach, describe, expect, it } from 'vitest';
import { CREDENTIAL_KEY_BYTES, resetEnvCache } from '@ctem/config';
import { decryptIntegrationSecret, encryptIntegrationSecret } from './credential-crypto';

const KEY = Buffer.alloc(CREDENTIAL_KEY_BYTES, 9).toString('base64');
const TOKEN = 'ghp_super_secret_token_value_0123456789';
const ORG_A = '00000000-0000-4000-8000-0000000000a1';
const ORG_B = '00000000-0000-4000-8000-0000000000b2';
const INT_A = '00000000-0000-4000-8000-0000000000c3';
const INT_B = '00000000-0000-4000-8000-0000000000d4';

afterEach(() => {
  delete process.env.CREDENTIAL_ENCRYPTION_KEY;
  resetEnvCache();
});

describe('integration secret crypto', () => {
  it('stores ciphertext that is not the token and round-trips with the same AAD', () => {
    process.env.CREDENTIAL_ENCRYPTION_KEY = KEY;
    resetEnvCache();
    const enc = encryptIntegrationSecret(TOKEN, ORG_A, INT_A);
    expect(enc.ciphertext.equals(Buffer.from(TOKEN))).toBe(false);
    expect(enc.ciphertext.includes(Buffer.from(TOKEN))).toBe(false);
    expect(enc.iv.length).toBe(12);
    expect(enc.authTag.length).toBe(16);
    expect(decryptIntegrationSecret(enc, ORG_A, INT_A)).toBe(TOKEN);
  });

  it('fails when the AAD org or integration does not match', () => {
    process.env.CREDENTIAL_ENCRYPTION_KEY = KEY;
    resetEnvCache();
    const enc = encryptIntegrationSecret(TOKEN, ORG_A, INT_A);
    expect(() => decryptIntegrationSecret(enc, ORG_B, INT_A)).toThrow(/could not be decrypted/);
    expect(() => decryptIntegrationSecret(enc, ORG_A, INT_B)).toThrow(/could not be decrypted/);
    try {
      decryptIntegrationSecret(enc, ORG_B, INT_A);
    } catch (err) {
      expect(String(err)).not.toContain(TOKEN);
    }
  });

  it('fails closed when the key is missing and does not echo the token', () => {
    delete process.env.CREDENTIAL_ENCRYPTION_KEY;
    resetEnvCache();
    expect(() => encryptIntegrationSecret(TOKEN, ORG_A, INT_A)).toThrow(
      /CREDENTIAL_ENCRYPTION_KEY is not configured/,
    );
    try {
      encryptIntegrationSecret(TOKEN, ORG_A, INT_A);
    } catch (err) {
      expect(String(err)).not.toContain(TOKEN);
    }
  });
});
