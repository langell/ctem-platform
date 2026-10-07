import { z } from 'zod';

/**
 * One schema for every service. A service that boots with a missing variable
 * fails at startup with a readable error rather than at first request.
 */

/** Production GitHub API origin. Any other value fails boot when NODE_ENV=production. */
export const GITHUB_API_PRODUCTION_URL = 'https://api.github.com';

export const CREDENTIAL_KEY_BYTES = 32;
export const CREDENTIAL_KEY_ID = 'v1';

/** Decode a 32-byte base64 key. Returns null when the value is missing or the wrong length. */
export function decodeCredentialEncryptionKey(value: string | undefined): Buffer | null {
  if (!value) return null;
  const trimmed = value.trim();
  if (!trimmed || !/^[A-Za-z0-9+/]+={0,2}$/.test(trimmed)) return null;
  const key = Buffer.from(trimmed, 'base64');
  if (key.length !== CREDENTIAL_KEY_BYTES) return null;
  return key;
}

/**
 * Origin-only http(s) URL: no userinfo, path, query, or fragment.
 * Shared by non-production CTEM_GITHUB_API_URL and by CTEM_ORIGIN.
 */
export function originOnlyIssue(url: string): string | null {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return 'must be an absolute http(s) URL';
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return 'must use http or https';
  }
  if (parsed.username || parsed.password) return 'must not embed userinfo';
  if (!parsed.hostname) return 'must include a host';
  if (parsed.pathname !== '/' && parsed.pathname !== '') return 'must not include a path';
  if (parsed.search || parsed.hash) return 'must not include a query or fragment';
  return null;
}

/**
 * Non-production CTEM_GITHUB_API_URL may be the public API or a local stub.
 * Production is an exact string match — the stub host is not special-cased here.
 * The platform does not read GITHUB_API_URL: GitHub Actions sets that name to
 * https://api.github.com and a workflow step cannot override it.
 */
export function githubApiUrlIssue(url: string, nodeEnv: string): string | null {
  if (nodeEnv === 'production') {
    if (url !== GITHUB_API_PRODUCTION_URL) {
      return `must be exactly ${GITHUB_API_PRODUCTION_URL} when NODE_ENV=production`;
    }
    return null;
  }
  return originOnlyIssue(url);
}

/**
 * Public web origin for invite links. Same origin-only checks as
 * githubApiUrlIssue, and https when NODE_ENV=production.
 */
export function ctemOriginIssue(url: string, nodeEnv: string): string | null {
  const issue = originOnlyIssue(url);
  if (issue) return issue;
  if (nodeEnv === 'production' && new URL(url).protocol !== 'https:') {
    return 'must use https when NODE_ENV=production';
  }
  return null;
}

export const EnvSchema = z
  .object({
    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
    SERVICE_NAME: z.string().default('ctem-service'),
    PORT: z.coerce.number().int().default(3000),
    LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace']).default('info'),

    DATABASE_URL: z.string().default('postgresql://ctem:ctem@localhost:5432/ctem?schema=public'),
    /** Non-superuser role that RLS actually applies to. Migrations use DATABASE_URL. */
    DATABASE_APP_URL: z.string().optional(),

    REDIS_URL: z.string().default('redis://localhost:6379'),

    NATS_URL: z.string().default('nats://localhost:4222'),
    NATS_STREAM_PREFIX: z.string().default('CTEM'),

    S3_ENDPOINT: z.string().default('http://localhost:9000'),
    S3_REGION: z.string().default('us-east-1'),
    S3_BUCKET: z.string().default('ctem-artifacts'),
    S3_ACCESS_KEY_ID: z.string().default('ctem'),
    S3_SECRET_ACCESS_KEY: z.string().default('ctem-secret'),
    S3_FORCE_PATH_STYLE: z.coerce.boolean().default(true),
    /**
     * Server-side encryption for artifacts. Defaults to AES256 in production and
     * none elsewhere — local MinIO rejects SSE unless a KMS is configured.
     */
    S3_SSE: z.enum(['none', 'AES256', 'aws:kms']).optional(),

    /** OIDC issuer for human logins; JWKS is fetched and cached from here. */
    OIDC_ISSUER: z.string().default('http://localhost:8080/realms/ctem'),
    OIDC_AUDIENCE: z.string().default('ctem-api'),
    JWT_PUBLIC_KEY: z.string().optional(),
    /** HMAC key used to sign the internal principal header between services. */
    INTERNAL_TOKEN_SECRET: z.string().default('dev-internal-secret-change-me'),

    ASSET_SERVICE_URL: z.string().default('http://localhost:3002'),
    IDENTITY_SERVICE_URL: z.string().default('http://localhost:3001'),
    ORCHESTRATOR_SERVICE_URL: z.string().default('http://localhost:3003'),
    FINDINGS_SERVICE_URL: z.string().default('http://localhost:3004'),
    RISK_SERVICE_URL: z.string().default('http://localhost:3005'),
    REPORTING_SERVICE_URL: z.string().default('http://localhost:3006'),
    NOTIFICATION_SERVICE_URL: z.string().default('http://localhost:3007'),

    /**
     * GitHub REST API base. Tenants cannot set this. Production boot requires
     * exactly https://api.github.com. Other http(s) origins are the dev/test
     * stub exception and are rejected when NODE_ENV=production.
     * Named CTEM_GITHUB_API_URL because GITHUB_API_URL is reserved by GitHub
     * Actions and a step env block cannot replace it.
     */
    CTEM_GITHUB_API_URL: z.string().default(GITHUB_API_PRODUCTION_URL),
    /**
     * AES-256-GCM key for per-tenant integration secrets (32 bytes, base64).
     * Required in production. Intentionally not an env: connector name.
     */
    CREDENTIAL_ENCRYPTION_KEY: z.string().optional(),

    /** Vulnerability intelligence feeds consumed by the SCA scanner and risk service. */
    OSV_API_URL: z.string().default('https://api.osv.dev/v1'),
    NVD_API_URL: z.string().default('https://services.nvd.nist.gov/rest/json'),
    NVD_API_KEY: z.string().optional(),
    EPSS_API_URL: z.string().default('https://api.first.org/data/v1/epss'),
    KEV_FEED_URL: z
      .string()
      .default(
        'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
      ),

    SCANNER_CONCURRENCY: z.coerce.number().int().min(1).default(4),
    SCANNER_JOB_TIMEOUT_MS: z.coerce
      .number()
      .int()
      .default(15 * 60 * 1000),

    /**
     * Public web origin for invite links (`${CTEM_ORIGIN}/invite#token=…`).
     * Origin only. Production must be https.
     */
    CTEM_ORIGIN: z.string().default('http://localhost:3000'),
    /**
     * Invite mail. `none` sends nothing. `smtp` is a generic SMTP adapter
     * (nodemailer). The schema does not special-case a provider host.
     */
    CTEM_MAIL_TRANSPORT: z.enum(['none', 'smtp']).default('none'),
    CTEM_SMTP_HOST: z.string().default('localhost'),
    CTEM_SMTP_PORT: z.coerce.number().int().min(1).max(65535).default(1025),
    /** Local Mailpit uses `none`. Production must be `starttls` or `tls`. */
    CTEM_SMTP_SECURITY: z.enum(['none', 'starttls', 'tls']).default('none'),
    CTEM_SMTP_USER: z.string().optional(),
    /** Secret. Required in production when CTEM_MAIL_TRANSPORT=smtp. */
    CTEM_SMTP_PASSWORD: z.string().optional(),
    /**
     * From address. The dev stub is local. Production does not assume a
     * sender; set CTEM_MAIL_FROM when one is chosen.
     */
    CTEM_MAIL_FROM: z.string().default('CTEM <invites@localhost>'),
  })
  .superRefine((env, ctx) => {
    const urlIssue = githubApiUrlIssue(env.CTEM_GITHUB_API_URL, env.NODE_ENV);
    if (urlIssue) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['CTEM_GITHUB_API_URL'],
        message: urlIssue,
      });
    }
    const key = decodeCredentialEncryptionKey(env.CREDENTIAL_ENCRYPTION_KEY);
    if (env.NODE_ENV === 'production' && !key) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['CREDENTIAL_ENCRYPTION_KEY'],
        message: 'required in production and must be 32 bytes, base64',
      });
    } else if (env.CREDENTIAL_ENCRYPTION_KEY?.trim() && !key) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['CREDENTIAL_ENCRYPTION_KEY'],
        message: 'must be 32 bytes, base64',
      });
    }
    const originIssue = ctemOriginIssue(env.CTEM_ORIGIN, env.NODE_ENV);
    if (originIssue) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['CTEM_ORIGIN'],
        message: originIssue,
      });
    }
    if (env.NODE_ENV === 'production' && env.CTEM_SMTP_SECURITY === 'none') {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['CTEM_SMTP_SECURITY'],
        message: 'must be starttls or tls when NODE_ENV=production',
      });
    }
    if (env.CTEM_MAIL_TRANSPORT === 'smtp') {
      if (!env.CTEM_SMTP_HOST.trim()) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['CTEM_SMTP_HOST'],
          message: 'required when CTEM_MAIL_TRANSPORT=smtp',
        });
      }
      if (!env.CTEM_MAIL_FROM.trim()) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['CTEM_MAIL_FROM'],
          message: 'required when CTEM_MAIL_TRANSPORT=smtp',
        });
      }
      if (env.NODE_ENV === 'production') {
        if (!env.CTEM_SMTP_USER?.trim()) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: ['CTEM_SMTP_USER'],
            message: 'required in production when CTEM_MAIL_TRANSPORT=smtp',
          });
        }
        if (!env.CTEM_SMTP_PASSWORD?.trim()) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: ['CTEM_SMTP_PASSWORD'],
            message: 'required in production when CTEM_MAIL_TRANSPORT=smtp',
          });
        }
      }
    }
  });

export type Env = z.infer<typeof EnvSchema>;

let cached: Env | null = null;

export function loadEnv(source: NodeJS.ProcessEnv = process.env): Env {
  if (cached) return cached;
  const parsed = EnvSchema.safeParse(source);
  if (!parsed.success) {
    const issues = parsed.error.issues
      .map((i) => `  - ${i.path.join('.')}: ${i.message}`)
      .join('\n');
    throw new Error(`Invalid environment configuration:\n${issues}`);
  }
  cached = parsed.data;
  return cached;
}

export function resetEnvCache(): void {
  cached = null;
}
