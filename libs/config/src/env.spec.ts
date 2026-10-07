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

describe('CTEM_GITHUB_API_URL production gate', () => {
  it('rejects the stub URL when NODE_ENV is production', () => {
    const parsed = EnvSchema.safeParse({
      NODE_ENV: 'production',
      CTEM_GITHUB_API_URL: STUB_URL,
      CREDENTIAL_ENCRYPTION_KEY: DEV_KEY,
    });
    expect(parsed.success).toBe(false);
    if (!parsed.success) {
      const issue = parsed.error.issues.find(
        (item) => item.path.join('.') === 'CTEM_GITHUB_API_URL',
      );
      expect(issue?.message).toContain(GITHUB_API_PRODUCTION_URL);
      expect(issue?.message).toContain('production');
    }
  });

  it('rejects a github-stub hostname when NODE_ENV is production', () => {
    const parsed = EnvSchema.safeParse({
      NODE_ENV: 'production',
      CTEM_GITHUB_API_URL: 'http://github-stub:4019',
      CREDENTIAL_ENCRYPTION_KEY: DEV_KEY,
    });
    expect(parsed.success).toBe(false);
  });

  it('accepts exactly https://api.github.com in production when the key is set', () => {
    const parsed = EnvSchema.safeParse({
      NODE_ENV: 'production',
      CTEM_GITHUB_API_URL: GITHUB_API_PRODUCTION_URL,
      CREDENTIAL_ENCRYPTION_KEY: DEV_KEY,
      CTEM_ORIGIN: 'https://ctem.example.com',
      CTEM_SMTP_SECURITY: 'starttls',
    });
    expect(parsed.success).toBe(true);
    if (parsed.success) expect(parsed.data.CTEM_GITHUB_API_URL).toBe(GITHUB_API_PRODUCTION_URL);
  });

  it('fails closed at boot when the production encryption key is missing', () => {
    expect(() =>
      loadEnv({
        NODE_ENV: 'production',
        CTEM_GITHUB_API_URL: GITHUB_API_PRODUCTION_URL,
      }),
    ).toThrow(/CREDENTIAL_ENCRYPTION_KEY/);
  });

  it('allows the loopback stub when NODE_ENV is not production', () => {
    const parsed = EnvSchema.safeParse({
      NODE_ENV: 'development',
      CTEM_GITHUB_API_URL: STUB_URL,
    });
    expect(parsed.success).toBe(true);
    if (parsed.success) expect(parsed.data.CTEM_GITHUB_API_URL).toBe(STUB_URL);
  });

  it('does not boot production config that points at the stub', () => {
    expect(() =>
      loadEnv({
        NODE_ENV: 'production',
        CTEM_GITHUB_API_URL: STUB_URL,
        CREDENTIAL_ENCRYPTION_KEY: DEV_KEY,
      }),
    ).toThrow(/api\.github\.com/);
  });

  it('ignores the Actions GitHub API variable and keeps the platform key', () => {
    // GitHub Actions sets GITHUB_API_URL; that name is not in this schema.
    const actionsName = 'GITHUB_' + 'API_URL';
    const parsed = EnvSchema.safeParse({
      NODE_ENV: 'development',
      [actionsName]: STUB_URL,
      CTEM_GITHUB_API_URL: GITHUB_API_PRODUCTION_URL,
    });
    expect(parsed.success).toBe(true);
    if (parsed.success) {
      expect(parsed.data.CTEM_GITHUB_API_URL).toBe(GITHUB_API_PRODUCTION_URL);
      expect(parsed.data).not.toHaveProperty(actionsName);
    }
  });
});

function issueMessage(
  parsed: ReturnType<typeof EnvSchema.safeParse>,
  path: string,
): string | undefined {
  if (parsed.success) return undefined;
  return parsed.error.issues.find((item) => item.path.join('.') === path)?.message;
}

describe('invite mail env', () => {
  const productionBase = {
    NODE_ENV: 'production' as const,
    CTEM_GITHUB_API_URL: GITHUB_API_PRODUCTION_URL,
    CREDENTIAL_ENCRYPTION_KEY: DEV_KEY,
    CTEM_ORIGIN: 'https://ctem.example.com',
    CTEM_SMTP_SECURITY: 'starttls' as const,
  };

  it('defaults to a local origin, Mailpit SMTP settings, and a silent transport', () => {
    const parsed = EnvSchema.safeParse({});
    expect(parsed.success).toBe(true);
    if (!parsed.success) return;
    expect(parsed.data.CTEM_ORIGIN).toBe('http://localhost:3000');
    expect(parsed.data.CTEM_MAIL_TRANSPORT).toBe('none');
    expect(parsed.data.CTEM_SMTP_HOST).toBe('localhost');
    expect(parsed.data.CTEM_SMTP_PORT).toBe(1025);
    expect(parsed.data.CTEM_SMTP_SECURITY).toBe('none');
    expect(parsed.data.CTEM_SMTP_USER).toBeUndefined();
    expect(parsed.data.CTEM_SMTP_PASSWORD).toBeUndefined();
    expect(parsed.data.CTEM_MAIL_FROM).toBe('CTEM <invites@localhost>');
  });

  it('coerces the SMTP port', () => {
    const parsed = EnvSchema.safeParse({ CTEM_SMTP_PORT: '1025' });
    expect(parsed.success).toBe(true);
    if (parsed.success) expect(parsed.data.CTEM_SMTP_PORT).toBe(1025);
  });

  it('rejects an SMTP port outside 1-65535', () => {
    expect(EnvSchema.safeParse({ CTEM_SMTP_PORT: '0' }).success).toBe(false);
    expect(EnvSchema.safeParse({ CTEM_SMTP_PORT: '70000' }).success).toBe(false);
  });

  it('rejects a mail transport other than none or smtp', () => {
    expect(EnvSchema.safeParse({ CTEM_MAIL_TRANSPORT: 'postmark' }).success).toBe(false);
  });

  it('allows http origin, security none, and no SMTP credentials outside production', () => {
    const parsed = EnvSchema.safeParse({
      NODE_ENV: 'development',
      CTEM_ORIGIN: 'http://localhost:3000',
      CTEM_MAIL_TRANSPORT: 'smtp',
      CTEM_SMTP_SECURITY: 'none',
      CTEM_MAIL_FROM: 'CTEM <invites@localhost>',
    });
    expect(parsed.success).toBe(true);
  });

  it('rejects an origin with a path, query, fragment, or userinfo', () => {
    for (const origin of [
      'http://localhost:3000/app',
      'http://localhost:3000?x=1',
      'http://localhost:3000#token=secret',
      'http://user:pass@localhost:3000',
      'ftp://localhost:3000',
      'not a url',
    ]) {
      const parsed = EnvSchema.safeParse({ CTEM_ORIGIN: origin });
      expect(parsed.success, origin).toBe(false);
      expect(issueMessage(parsed, 'CTEM_ORIGIN')).toBeTruthy();
    }
  });

  it('rejects an http origin in production', () => {
    const parsed = EnvSchema.safeParse({
      ...productionBase,
      CTEM_ORIGIN: 'http://ctem.example.com',
    });
    expect(parsed.success).toBe(false);
    expect(issueMessage(parsed, 'CTEM_ORIGIN')).toContain('https');
  });

  it('rejects SMTP security none in production even when mail is disabled', () => {
    const parsed = EnvSchema.safeParse({
      ...productionBase,
      CTEM_MAIL_TRANSPORT: 'none',
      CTEM_SMTP_SECURITY: 'none',
    });
    expect(parsed.success).toBe(false);
    expect(issueMessage(parsed, 'CTEM_SMTP_SECURITY')).toContain('starttls');
  });

  it('boots production with mail disabled and no provider credentials', () => {
    const parsed = EnvSchema.safeParse({
      ...productionBase,
      CTEM_MAIL_TRANSPORT: 'none',
      CTEM_SMTP_HOST: 'smtp.postmarkapp.com',
      CTEM_SMTP_PORT: '587',
    });
    expect(parsed.success).toBe(true);
    if (!parsed.success) return;
    expect(parsed.data.CTEM_SMTP_USER).toBeUndefined();
    expect(parsed.data.CTEM_SMTP_PASSWORD).toBeUndefined();
  });

  it('requires SMTP user and password in production when transport is smtp', () => {
    const missing = EnvSchema.safeParse({
      ...productionBase,
      CTEM_MAIL_TRANSPORT: 'smtp',
      CTEM_SMTP_HOST: 'smtp.postmarkapp.com',
      CTEM_SMTP_PORT: 587,
      CTEM_MAIL_FROM: 'CTEM <invites@localhost>',
    });
    expect(missing.success).toBe(false);
    expect(issueMessage(missing, 'CTEM_SMTP_USER')).toContain('production');
    expect(issueMessage(missing, 'CTEM_SMTP_PASSWORD')).toContain('production');

    const ready = EnvSchema.safeParse({
      ...productionBase,
      CTEM_MAIL_TRANSPORT: 'smtp',
      CTEM_SMTP_HOST: 'smtp.example.com',
      CTEM_SMTP_PORT: 587,
      CTEM_SMTP_USER: 'server-token',
      CTEM_SMTP_PASSWORD: 'server-token',
      CTEM_MAIL_FROM: 'CTEM <invites@localhost>',
    });
    expect(ready.success).toBe(true);
  });

  it('requires a from address and host when transport is smtp', () => {
    const parsed = EnvSchema.safeParse({
      NODE_ENV: 'development',
      CTEM_MAIL_TRANSPORT: 'smtp',
      CTEM_SMTP_HOST: '  ',
      CTEM_MAIL_FROM: '',
    });
    expect(parsed.success).toBe(false);
    expect(issueMessage(parsed, 'CTEM_SMTP_HOST')).toContain('smtp');
    expect(issueMessage(parsed, 'CTEM_MAIL_FROM')).toContain('smtp');
  });

  it('accepts tls as a production SMTP security mode', () => {
    const parsed = EnvSchema.safeParse({
      ...productionBase,
      CTEM_SMTP_SECURITY: 'tls',
    });
    expect(parsed.success).toBe(true);
  });
});
