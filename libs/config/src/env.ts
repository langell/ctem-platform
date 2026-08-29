import { z } from 'zod';

/**
 * One schema for every service. A service that boots with a missing variable
 * fails at startup with a readable error rather than at first request.
 */
export const EnvSchema = z.object({
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

  /** GitHub REST API base for the discovery connector; tests point it at a stub. */
  GITHUB_API_URL: z.string().default('https://api.github.com'),

  /** Vulnerability intelligence feeds consumed by the SCA scanner and risk service. */
  OSV_API_URL: z.string().default('https://api.osv.dev/v1'),
  NVD_API_URL: z.string().default('https://services.nvd.nist.gov/rest/json'),
  NVD_API_KEY: z.string().optional(),
  EPSS_API_URL: z.string().default('https://api.first.org/data/v1/epss'),
  KEV_FEED_URL: z
    .string()
    .default('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'),

  SCANNER_CONCURRENCY: z.coerce.number().int().min(1).default(4),
  SCANNER_JOB_TIMEOUT_MS: z.coerce.number().int().default(15 * 60 * 1000),
});

export type Env = z.infer<typeof EnvSchema>;

let cached: Env | null = null;

export function loadEnv(source: NodeJS.ProcessEnv = process.env): Env {
  if (cached) return cached;
  const parsed = EnvSchema.safeParse(source);
  if (!parsed.success) {
    const issues = parsed.error.issues.map((i) => `  - ${i.path.join('.')}: ${i.message}`).join('\n');
    throw new Error(`Invalid environment configuration:\n${issues}`);
  }
  cached = parsed.data;
  return cached;
}

export function resetEnvCache(): void {
  cached = null;
}
