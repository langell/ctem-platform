import { z } from 'zod';

/** GitHub login: one leading alphanumeric, no leading or trailing hyphen. */
const GitHubOwner = z
  .string()
  .trim()
  .min(1)
  .max(39)
  .regex(/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/);

/**
 * Tenant connect body. Org, provider, credentialRef, config, and base URL
 * are not accepted — the principal and the platform GITHUB_API_URL supply them.
 */
export const ConnectGitHubRequest = z
  .object({
    owner: GitHubOwner,
    ownerType: z.enum(['user', 'org']),
    token: z.string().trim().min(1).max(2048),
    displayName: z.string().trim().min(1).max(120).optional(),
  })
  .strict();
export type ConnectGitHubRequest = z.infer<typeof ConnectGitHubRequest>;

/** Public integration row. Never includes the token, credentialRef, or ciphertext. */
export const IntegrationView = z
  .object({
    id: z.string().uuid(),
    provider: z.string(),
    displayName: z.string(),
    owner: z.string(),
    ownerType: z.enum(['user', 'org']),
    enabled: z.boolean(),
    hasCredential: z.boolean(),
    lastSyncAt: z.string().datetime().nullable(),
    lastSyncError: z.string().nullable(),
  })
  .strict();
export type IntegrationView = z.infer<typeof IntegrationView>;
