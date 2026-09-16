/**
 * Allowlisted GitLab Deployments context on the scan row (`options.gitlab` or
 * the same keys at the top level of `options`). Client keys that set a deploy
 * or CI conclusion stay refused on create (`CLIENT_CONCLUSION_KEYS`); any
 * nested `deployConclusion` here is ignored — `concludeDeploy` is the only
 * source.
 *
 * Required to publish:
 *   - `projectId` — same shape as Commit Status (#63): preferred GitLab
 *     `path/with/namespace` (e.g. `acme/api`); also a positive integer project id
 *   - `deploymentId` — positive integer GitLab deployment id
 * Optional:
 *   - `environment` — attribute only (not a host / API endpoint). GitLab PUT
 *     does not take environment; CTEM never POSTs a Deployment to create one.
 *
 * Missing `sha` is OK for this publisher (sha remains Commit-Status-only).
 * Tenant `baseUrl` / `apiUrl` / `EXTRA_GITLAB_HOST_KEYS` on the scan are
 * ignored and never used as the API host. Origin is gitlab.com or the scan
 * asset's GitLab AssetConnector `baseUrl`.
 */

import { parseGitLabProjectId } from './gitlab-statuses.context';

export interface GitlabDeploymentsContext {
  projectId: string;
  deploymentId: number;
  environment?: string;
}

function asRecord(value: unknown): Record<string, unknown> {
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  return {};
}

function stringField(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  return trimmed.length ? trimmed : undefined;
}

function looksLikeUrl(value: string): boolean {
  return /:\/\//.test(value) || /@/.test(value);
}

/** Positive GitLab deployment id. Strings of digits allowed; floats / 0 / hex refused. */
export function parseGitlabDeploymentId(value: unknown): number | null {
  if (typeof value === 'number') {
    if (!Number.isInteger(value) || value <= 0 || value > Number.MAX_SAFE_INTEGER) return null;
    return value;
  }
  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (!/^[1-9][0-9]{0,15}$/.test(trimmed)) return null;
    const n = Number(trimmed);
    if (!Number.isInteger(n) || n <= 0 || n > Number.MAX_SAFE_INTEGER) return null;
    return n;
  }
  return null;
}

/**
 * Environment is copied onto the context for logging only. It is never
 * concatenated into an API URL. URLs / userinfo are omitted (not a scan failure).
 */
function parseEnvironment(raw: string | undefined): string | undefined {
  if (!raw) return undefined;
  const name = raw.replace(/[\r\n\0]/g, ' ').trim();
  if (!name || looksLikeUrl(name)) return undefined;
  return name.slice(0, 100);
}

export function parseGitlabDeploymentsContext(options: unknown): GitlabDeploymentsContext | null {
  const opts = asRecord(options);
  const gitlab = asRecord(opts.gitlab);
  // Tenant endpoint keys (baseUrl, apiUrl, host, …) are ignored — they must
  // never become the API host.

  const projectId = parseGitLabProjectId(gitlab.projectId ?? opts.projectId);
  const deploymentId = parseGitlabDeploymentId(gitlab.deploymentId ?? opts.deploymentId);
  if (!projectId || deploymentId == null) return null;

  const environment = parseEnvironment(
    stringField(gitlab.environment) ?? stringField(opts.environment),
  );

  return {
    projectId,
    deploymentId,
    ...(environment ? { environment } : {}),
  };
}
