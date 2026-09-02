import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { Injectable } from '@nestjs/common';
import { rootLogger } from '@ctem/observability';
import type { ScanJob } from '@ctem/contracts';
import type { ScanContext } from '@ctem/scanner-sdk';
import { isPrivateTarget, resolveGithubCredential } from './github.credential';

const execFileAsync = promisify(execFile);

const SAFE_REF = /^[A-Za-z0-9._/-]+$/;
const SCM_SEGMENT = /^[\w.-]+$/;
const ALLOWED_CLONE_HOSTS = new Set(['github.com', 'www.github.com', 'gitlab.com', 'www.gitlab.com']);

export class CheckoutError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CheckoutError';
  }
}

export interface RepoCheckout {
  checkout(ctx: ScanContext): Promise<void>;
}

export interface ResolvedCheckout {
  /** Allowlisted origin, never includes credentials. */
  url: string;
  token?: string;
}

/**
 * Shallow-clones the job target into the worker's existing `ctx.workDir`.
 * The SDK already creates and deletes that directory — this does not invent
 * a second sandbox.
 *
 * Egress is allowlisted: `https://github.com/owner/repo` or
 * `https://gitlab.com/owner/repo` (nested GitLab groups allowed) from
 * `cloneUrl`, or a `github:owner/repo` / `gitlab:owner/repo` externalKey.
 * The github:/gitlab: key is the asset identity: when both a cloneUrl and a
 * key are present they must canonicalize to the same host+path or the job
 * fails closed (a tenant-writable cloneUrl cannot redirect the clone).
 * Tenant-writable `htmlUrl` / `url` / `git@` are refused. Missing or refused
 * sources throw so the job fails closed instead of scanning an empty workDir.
 * Self-hosted GitLab is the connector `gitlabHost` (from `baseUrl`) — clone
 * and identity use that host, not an arbitrary hostname in cloneUrl.
 */
@Injectable()
export class GitRepoCheckout implements RepoCheckout {
  private readonly log = rootLogger.child({ component: 'git-checkout' });

  async checkout(ctx: ScanContext): Promise<void> {
    const resolved = resolveCheckout(ctx.job);
    this.log.info({ url: resolved.url, ref: resolveRef(ctx.job), workDir: ctx.workDir }, 'shallow checkout');
    const allowedHost = new URL(resolved.url).hostname;
    await shallowClone(resolved.url, resolveRef(ctx.job), ctx.workDir, {
      token: resolved.token,
      allowedHost,
    });
  }
}

/** Pure: throws on a missing, refused, or unauthenticated-private target. */
export function resolveCheckout(job: Pick<ScanJob, 'target' | 'credentialRef'>): ResolvedCheckout {
  const token = requireUsableCredential(job);
  const url = resolveCloneUrl(job.target);
  return token ? { url, token } : { url };
}

export function resolveCloneUrl(target: Record<string, unknown>): string {
  const gitlabHost = parseTargetGitlabHost(target);
  const hasCloneUrl = typeof target.cloneUrl === 'string' && target.cloneUrl.length > 0;
  const key = typeof target.externalKey === 'string' ? target.externalKey : undefined;
  const fromKey = key ? httpsFromScmIdentityKey(key, gitlabHost) : null;

  if (hasCloneUrl && fromKey) {
    const fromClone = allowlistedCloneHttps(target.cloneUrl as string, gitlabHost);
    if (canonicalHostPath(fromClone, gitlabHost) !== canonicalHostPath(fromKey, gitlabHost)) {
      throw new CheckoutError(
        `cloneUrl does not match asset identity '${key}' — refusing to clone a different repository`,
      );
    }
    return fromClone;
  }
  if (hasCloneUrl) {
    return allowlistedCloneHttps(target.cloneUrl as string, gitlabHost);
  }
  if (fromKey) {
    return fromKey;
  }
  throw new CheckoutError(
    'SCA source scan needs an allowlisted clone source (cloneUrl on github.com or gitlab.com, or github:owner/repo / gitlab:owner/repo). ' +
      'htmlUrl / url / git@ are refused so tenant-writable target metadata cannot drive scanner egress.',
  );
}

/** @deprecated use allowlistedCloneHttps — kept so existing imports keep working. */
export function allowlistedGithubHttps(raw: string): string {
  return allowlistedCloneHttps(raw);
}

export function allowlistedCloneHttps(raw: string, allowedGitlabHost?: string): string {
  if (raw.startsWith('git@') || raw.startsWith('ssh:')) {
    throw new CheckoutError(`Refusing git@ / ssh clone URL: ${raw}`);
  }
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new CheckoutError(`Refusing unparseable clone URL: ${raw}`);
  }
  if (parsed.protocol !== 'https:') {
    throw new CheckoutError(`Refusing non-https clone URL: ${raw}`);
  }
  const canonical = canonicalCloneHost(parsed.hostname, allowedGitlabHost);
  if (!canonical) {
    throw new CheckoutError(
      allowedGitlabHost
        ? `Refusing clone host '${parsed.hostname}' — only github.com, gitlab.com, and the configured GitLab host '${allowedGitlabHost}' are allowlisted`
        : `Refusing clone host '${parsed.hostname}' — only github.com and gitlab.com are allowlisted`,
    );
  }
  if (parsed.port && parsed.port !== '443') {
    throw new CheckoutError(`Refusing clone URL with non-default port: ${raw}`);
  }
  if (parsed.username || parsed.password) {
    throw new CheckoutError('Refusing clone URL that already embeds credentials');
  }
  const parts = parsed.pathname.replace(/\.git$/, '').split('/').filter(Boolean);
  if (canonical === 'github.com') {
    if (parts.length !== 2 || !parts.every((p) => SCM_SEGMENT.test(p))) {
      throw new CheckoutError(`Refusing clone URL with an unexpected GitHub path: ${raw}`);
    }
    return `https://github.com/${parts[0]}/${parts[1]}.git`;
  }
  if (parts.length < 2 || parts.length > 10 || !parts.every((p) => SCM_SEGMENT.test(p))) {
    throw new CheckoutError(`Refusing clone URL with an unexpected GitLab path: ${raw}`);
  }
  return `https://${canonical}/${parts.join('/')}.git`;
}

export function githubKeyToHttps(externalKey: string): string {
  const m = /^github:([\w.-]+)\/([\w.-]+)$/.exec(externalKey);
  if (!m) {
    throw new CheckoutError(`Refusing malformed github externalKey: ${externalKey}`);
  }
  return `https://github.com/${m[1]}/${m[2]}.git`;
}

export function gitlabKeyToHttps(externalKey: string, host = 'gitlab.com'): string {
  const m = /^gitlab:([\w.-]+(?:\/[\w.-]+)+)$/.exec(externalKey);
  if (!m) {
    throw new CheckoutError(`Refusing malformed gitlab externalKey: ${externalKey}`);
  }
  const parts = m[1].split('/');
  if (parts.length > 10) {
    throw new CheckoutError(`Refusing malformed gitlab externalKey: ${externalKey}`);
  }
  return `https://${host}/${m[1]}.git`;
}

/** github: / gitlab: keys only — other externalKeys are not clone identities. */
function httpsFromScmIdentityKey(externalKey: string, gitlabHost?: string): string | null {
  if (externalKey.startsWith('github:')) return githubKeyToHttps(externalKey);
  if (externalKey.startsWith('gitlab:')) return gitlabKeyToHttps(externalKey, gitlabHost ?? 'gitlab.com');
  return null;
}

/** Compare allowlisted clone origins as host+path. */
function canonicalHostPath(url: string, allowedGitlabHost?: string): string {
  const parsed = new URL(url);
  const host = canonicalCloneHost(parsed.hostname, allowedGitlabHost);
  if (!host) {
    throw new CheckoutError(
      allowedGitlabHost
        ? `Refusing clone host '${parsed.hostname}' — only github.com, gitlab.com, and the configured GitLab host '${allowedGitlabHost}' are allowlisted`
        : `Refusing clone host '${parsed.hostname}' — only github.com and gitlab.com are allowlisted`,
    );
  }
  const path = parsed.pathname.replace(/\.git$/, '').replace(/\/+$/, '');
  return `${host}${path}`.toLowerCase();
}

function canonicalCloneHost(hostname: string, allowedGitlabHost?: string): string | null {
  const host = hostname.toLowerCase().replace(/\.$/, '');
  if (host === 'github.com' || host === 'www.github.com') return 'github.com';
  if (host === 'gitlab.com' || host === 'www.gitlab.com') return 'gitlab.com';
  if (allowedGitlabHost && host === allowedGitlabHost) return allowedGitlabHost;
  return null;
}

/**
 * Connector-stamped GitLab origin from `baseUrl`. https-only, no userinfo,
 * no git@. This is the allowlisted clone host — not whatever cloneUrl says.
 */
function parseTargetGitlabHost(target: Record<string, unknown>): string | undefined {
  const raw = target.gitlabHost;
  if (typeof raw !== 'string' || raw.trim() === '') return undefined;
  const trimmed = raw.trim();
  if (trimmed.startsWith('git@') || trimmed.startsWith('ssh:') || trimmed.startsWith('ssh@')) {
    throw new CheckoutError(`Refusing git@ / ssh gitlabHost: ${trimmed}`);
  }
  if (trimmed.includes('@') && !trimmed.includes('://')) {
    throw new CheckoutError('Refusing gitlabHost that embeds userinfo');
  }
  const asUrl = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  let parsed: URL;
  try {
    parsed = new URL(asUrl);
  } catch {
    throw new CheckoutError(`Refusing unparseable gitlabHost: ${trimmed}`);
  }
  if (parsed.protocol !== 'https:') {
    throw new CheckoutError('Refusing non-https gitlabHost — only https is permitted');
  }
  if (parsed.username || parsed.password) {
    throw new CheckoutError('Refusing gitlabHost that embeds userinfo');
  }
  if (parsed.port && parsed.port !== '443') {
    throw new CheckoutError('Refusing gitlabHost with a non-default port');
  }
  const host = parsed.hostname.toLowerCase().replace(/\.$/, '');
  if (!host || host === 'github.com' || host === 'www.github.com') {
    throw new CheckoutError(`Refusing gitlabHost '${parsed.hostname}'`);
  }
  if (host === 'www.gitlab.com') return 'gitlab.com';
  return host;
}

function requireUsableCredential(job: Pick<ScanJob, 'target' | 'credentialRef'>): string | undefined {
  const privateRepo = isPrivateTarget(job.target);
  const ref = job.credentialRef;

  if (!ref && !privateRepo) return undefined;

  let token: string | undefined;
  try {
    token = resolveGithubCredential(ref);
  } catch (err) {
    throw new CheckoutError((err as Error).message);
  }

  if (!token) {
    if (ref) {
      throw new CheckoutError(
        `credentialRef '${ref}' is set but cannot be used — refusing to clone unauthenticated ` +
          '(private GitHub/GitLab assets would be missed; a public-only clone must not report empty success)',
      );
    }
    throw new CheckoutError(
      'Private repository requires a usable credentialRef (env:GITHUB_* or env:GITLAB_*). ' +
        'Refusing to clone unauthenticated.',
    );
  }
  return token;
}

/** `http.extraHeader` value. Never embed the PAT in the remote URL or .git/config. */
export function githubHttpExtraHeader(token: string): string {
  return basicAuthExtraHeader('x-access-token', token);
}

/** GitLab HTTPS PAT — same extraHeader path, oauth2 basic user. */
export function gitlabHttpExtraHeader(token: string): string {
  return basicAuthExtraHeader('oauth2', token);
}

export function cloneHttpExtraHeader(url: string, token: string): string {
  const host = new URL(url).hostname.toLowerCase();
  if (host === 'github.com' || host === 'www.github.com') return githubHttpExtraHeader(token);
  return gitlabHttpExtraHeader(token);
}

function basicAuthExtraHeader(user: string, token: string): string {
  const basic = Buffer.from(`${user}:${token}`, 'utf8').toString('base64');
  return `AUTHORIZATION: basic ${basic}`;
}

export function resolveRef(job: { options: Record<string, unknown>; target: Record<string, unknown> }): string {
  const candidates = [job.options.ref, job.options.commitSha, job.target.ref, job.target.defaultBranch, 'HEAD'];
  for (const value of candidates) {
    if (typeof value === 'string' && value.length > 0) return value;
  }
  return 'HEAD';
}

export function gitCheckoutCommands(url: string, ref: string, dest: string): string[][] {
  return [
    ['init', dest],
    ['-C', dest, 'remote', 'add', 'origin', url],
    ['-C', dest, 'fetch', '--depth', '1', '--', 'origin', ref],
    ['-C', dest, '-c', 'advice.detachedHead=false', 'checkout', 'FETCH_HEAD'],
  ];
}

export async function shallowClone(
  url: string,
  ref: string,
  dest: string,
  options: { exec?: typeof execFileAsync; token?: string; allowedHost?: string } = {},
): Promise<void> {
  const exec = options.exec ?? execFileAsync;
  if (!SAFE_REF.test(ref)) {
    throw new CheckoutError(`Refusing to checkout unsafe git ref: ${ref}`);
  }
  try {
    const parsed = new URL(url);
    const host = parsed.hostname.toLowerCase();
    const allowed =
      ALLOWED_CLONE_HOSTS.has(parsed.hostname) ||
      (options.allowedHost != null && host === options.allowedHost.toLowerCase());
    if (parsed.protocol !== 'https:' || !allowed) {
      throw new CheckoutError(`Refusing to clone URL with unsupported scheme or host`);
    }
    if (parsed.username || parsed.password) {
      throw new CheckoutError('Refusing clone URL that already embeds credentials');
    }
  } catch (err) {
    if (err instanceof CheckoutError) throw err;
    throw new CheckoutError(`Refusing unparseable clone URL`);
  }
  const env: NodeJS.ProcessEnv = { ...process.env, GIT_TERMINAL_PROMPT: '0', GIT_ASKPASS: 'echo' };
  if (options.token) {
    // extraHeader via git's env config — not argv, not remote URL, not .git/config.
    env.GIT_CONFIG_COUNT = '1';
    env.GIT_CONFIG_KEY_0 = 'http.extraHeader';
    env.GIT_CONFIG_VALUE_0 = cloneHttpExtraHeader(url, options.token);
  }
  for (const args of gitCheckoutCommands(url, ref, dest)) {
    await exec('git', args, { timeout: 60_000, env });
  }
}
