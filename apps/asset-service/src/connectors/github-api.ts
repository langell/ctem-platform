import { loadEnv, type Env } from '@ctem/config';

/**
 * GitHub API URL on the origin `@ctem/config` already accepted.
 * Stub hosts are not listed here. A stub origin is reachable only when
 * loadEnv() returned that URL.
 */
export class GithubApiUrlError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'GithubApiUrlError';
  }
}

export function githubApiUrl(pathAndQuery: string, env: Env = loadEnv()): string {
  const base = new URL(env.CTEM_GITHUB_API_URL);
  const dest = new URL(pathAndQuery, base);
  if (dest.origin !== base.origin) {
    throw new GithubApiUrlError('Refusing GitHub API host outside the platform GitHub API origin');
  }
  if (dest.username || dest.password) {
    throw new GithubApiUrlError('Refusing GitHub API URL that embeds userinfo');
  }
  return dest.toString();
}
