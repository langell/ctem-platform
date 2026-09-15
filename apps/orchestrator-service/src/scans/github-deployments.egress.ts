/**
 * GitHub Deployment status egress. Same allowlist as Checks: HTTPS
 * `api.github.com` only (no GitHub Enterprise, no tenant `baseUrl`, no follow
 * of platform `GITHUB_API_URL`). `repository` and `environment` are identifiers
 * / status attributes — never endpoints.
 */

import { githubChecksApiUrl } from './github-checks.egress';

export {
  GITHUB_API_HOST,
  GITHUB_API_ORIGIN,
  allowlistedGithubApiUrl,
} from './github-checks.egress';

/** List/create Deployment statuses on api.github.com. */
export function deploymentStatusesUrl(owner: string, repo: string, deploymentId: number): string {
  return githubChecksApiUrl(
    `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/deployments/${deploymentId}/statuses`,
  );
}
