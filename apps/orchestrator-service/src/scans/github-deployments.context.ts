/**
 * Allowlisted GitHub Deployments context on the scan row (`options.github` or
 * the same keys at the top level of `options`). Client keys that set a deploy
 * or Check conclusion stay refused on create (`CLIENT_CONCLUSION_KEYS`); any
 * nested `deployConclusion` here is ignored — `concludeDeploy` is the only
 * source.
 *
 * Required to publish:
 *   - `repository` — `owner/name` (or `owner` + `repo`); same parse as Checks
 *   - `deploymentId` — positive integer GitHub deployment id
 * Optional:
 *   - `environment` — status attribute only (not a host / API endpoint)
 *   - `description` — extra text; identity still includes `scanId`
 *   - `logUrl` — must be a CTEM URL (`CTEM_PUBLIC_URL` origin + scan path) or omit
 *
 * Tenant `baseUrl` / GHE host keys are ignored and never used as the API host.
 * Missing `repository` + `deploymentId` → no Deployment API call.
 */

import { allowlistedCtemDetailsUrl, parseGithubRepository } from './github-checks.context';

export interface GithubDeploymentsContext {
  owner: string;
  repo: string;
  deploymentId: number;
  environment?: string;
  description?: string;
  logUrl?: string;
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

/** Positive GitHub deployment id. Strings of digits allowed; floats / 0 / hex refused. */
export function parseGithubDeploymentId(value: unknown): number | null {
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
 * Environment is copied onto the status JSON only. It is never concatenated
 * into an API URL. URLs / userinfo are omitted (not a scan failure).
 */
function parseEnvironment(raw: string | undefined): string | undefined {
  if (!raw) return undefined;
  const name = raw.replace(/[\r\n\0]/g, ' ').trim();
  if (!name || looksLikeUrl(name)) return undefined;
  return name.slice(0, 100);
}

function parseExtraDescription(raw: string | undefined): string | undefined {
  if (!raw) return undefined;
  const text = raw.replace(/[\r\n\0]/g, ' ').trim();
  if (!text || looksLikeUrl(text)) return undefined;
  return text.slice(0, 80);
}

export function parseGithubDeploymentsContext(
  options: unknown,
  scanId: string,
): GithubDeploymentsContext | null {
  const opts = asRecord(options);
  const github = asRecord(opts.github);
  // Tenant endpoint keys (baseUrl, githubHost, …) are ignored — they must
  // never become the API host.

  const parsedRepo = parseGithubRepository(
    stringField(github.repository) ?? stringField(opts.repository),
    stringField(github.owner) ?? stringField(opts.owner),
    stringField(github.repo) ?? stringField(opts.repo),
  );
  const deploymentId = parseGithubDeploymentId(github.deploymentId ?? opts.deploymentId);
  if (!parsedRepo || deploymentId == null) return null;

  const environment = parseEnvironment(
    stringField(github.environment) ?? stringField(opts.environment),
  );
  const description = parseExtraDescription(
    stringField(github.description) ?? stringField(opts.description),
  );
  const logUrl = allowlistedCtemDetailsUrl(
    stringField(github.logUrl) ?? stringField(opts.logUrl),
    scanId,
  );

  return {
    owner: parsedRepo.owner,
    repo: parsedRepo.repo,
    deploymentId,
    ...(environment ? { environment } : {}),
    ...(description ? { description } : {}),
    ...(logUrl ? { logUrl } : {}),
  };
}
