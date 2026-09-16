/**
 * GitLab Deployments egress. Twin wrapper of Commit Status egress
 * (`gitlab-statuses.egress.ts`): gitlab.com is the default origin. A
 * self-hosted host is only the org GitLab AssetConnector `baseUrl` already
 * used for that asset/integration — https, no userinfo, no git@. Tenant scan
 * options cannot choose the API host (`EXTRA_GITLAB_HOST_KEYS` on the scan
 * are ignored and never become origin). Every fetch is re-pinned with
 * `allowlistedGitLabApiUrl`.
 *
 * This slice only GET/PUTs an existing deployment. There is no POST create
 * URL helper on purpose.
 */

import { gitlabStatusesApiUrl, type GitLabOrigin } from './gitlab-statuses.egress';

export {
  EXTRA_GITLAB_HOST_KEYS,
  GITLAB_COM,
  GITLAB_COM_API_URL,
  GITLAB_COM_HOST,
  GITLAB_COM_ORIGIN,
  allowlistedGitLabApiUrl,
  gitLabOriginFromScanJobs,
  parseGitLabBaseUrl,
  refuseExtraGitLabHosts,
  type GitLabOrigin,
} from './gitlab-statuses.egress';

/** GET one existing deployment, or PUT its status. Never a create collection. */
export function gitlabDeploymentUrl(
  origin: GitLabOrigin,
  projectId: string,
  deploymentId: number,
): string {
  return gitlabStatusesApiUrl(
    origin,
    `/projects/${encodeURIComponent(projectId)}/deployments/${deploymentId}`,
  );
}
