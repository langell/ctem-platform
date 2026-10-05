import { afterEach, describe, expect, it } from 'vitest';
import {
  CREDENTIAL_KEY_BYTES,
  EnvSchema,
  GITHUB_API_PRODUCTION_URL,
  loadEnv,
  resetEnvCache,
} from './env';

const DEV_KEY = Buffer.alloc(CREDENTIAL_KEY_BYTES, 7).toString('base64');
const STUB_URL = 'http://127.0.0.1:4019';

afterEach(() => {
  resetEnvCache();
});

describe('GITHUB_API_URL production gate', () => {
  it('rejects the stub URL when NODE_ENV is production', () => {
    const parsed = EnvSchema.safeParse({
      NODE_ENV: 'production',
      GITHUB_API_URL: STUB_URL,
      CREDENTIAL_ENCRYPTION_KEY: DEV_KEY,
    });
    expect(parsed.success).toBe(false);
    if (!parsed.success) {
      const issue = parsed.error.issues.find((item) => item.path.join('.') === 'GITHUB_API_URL');
      expect(issue?.message).toContain(GITHUB_API_PRODUCTION_URL);
      expect(issue?.message).toContain('production');
    }
  });

  it('rejects a github-stub hostname when NODE_ENV is production', () => {
    const parsed = EnvSchema.safeParse({
      NODE_ENV: 'production',
      GITHUB_API_URL: 'http://github-stub:4019',
      CREDENTIAL_ENCRYPTION_KEY: DEV_KEY,
    });
    expect(parsed.success).toBe(false);
  });

  it('accepts exactly https://api.github.com in production when the key is set', () => {
    const parsed = EnvSchema.safeParse({
      NODE_ENV: 'production',
      GITHUB_API_URL: GITHUB_API_PRODUCTION_URL,
      CREDENTIAL_ENCRYPTION_KEY: DEV_KEY,
    });
    expect(parsed.success).toBe(true);
  });

  it('fails closed at boot when the production encryption key is missing', () => {
    expect(() =>
      loadEnv({
        NODE_ENV: 'production',
        GITHUB_API_URL: GITHUB_API_PRODUCTION_URL,
      }),
    ).toThrow(/CREDENTIAL_ENCRYPTION_KEY/);
  });

  it('allows the loopback stub when NODE_ENV is not production', () => {
    const parsed = EnvSchema.safeParse({
      NODE_ENV: 'development',
      GITHUB_API_URL: STUB_URL,
    });
    expect(parsed.success).toBe(true);
    if (parsed.success) expect(parsed.data.GITHUB_API_URL).toBe(STUB_URL);
  });

  it('does not boot production config that points at the stub', () => {
    expect(() =>
      loadEnv({
        NODE_ENV: 'production',
        GITHUB_API_URL: STUB_URL,
        CREDENTIAL_ENCRYPTION_KEY: DEV_KEY,
      }),
    ).toThrow(/api\.github\.com/);
  });
});
