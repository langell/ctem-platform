import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { Injectable } from '@nestjs/common';
import { rootLogger } from '@ctem/observability';
import type { ScanJob } from '@ctem/contracts';
import type { ScanContext } from '@ctem/scanner-sdk';
import { isPrivateTarget, resolveGithubCredential } from './github.credential';

const execFileAsync = promisify(execFile);

const SAFE_REF = /^[A-Za-z0-9._/-]+$/;
const GITHUB_REPO = /^[\w.-]+$/;

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
 * Egress is allowlisted: only `https://github.com/owner/repo` from `cloneUrl`
 * or a `github:owner/repo` externalKey. Tenant-writable `htmlUrl` / `url` /
 * `git@` are refused. Missing or refused sources throw so the job fails
 * closed instead of scanning an empty workDir.
 */
@Injectable()
export class GitRepoCheckout implements RepoCheckout {
  private readonly log = rootLogger.child({ component: 'git-checkout' });

  async checkout(ctx: ScanContext): Promise<void> {
    const resolved = resolveCheckout(ctx.job);
    this.log.info({ url: resolved.url, ref: resolveRef(ctx.job), workDir: ctx.workDir }, 'shallow checkout');
    const fetchUrl = resolved.token ? withGithubToken(resolved.url, resolved.token) : resolved.url;
    await shallowClone(fetchUrl, resolveRef(ctx.job), ctx.workDir);
  }
}

/** Pure: throws on a missing, refused, or unauthenticated-private target. */
export function resolveCheckout(job: Pick<ScanJob, 'target' | 'credentialRef'>): ResolvedCheckout {
  const token = requireUsableCredential(job);
  const url = resolveCloneUrl(job.target);
  return token ? { url, token } : { url };
}

export function resolveCloneUrl(target: Record<string, unknown>): string {
  if (typeof target.cloneUrl === 'string' && target.cloneUrl.length > 0) {
    return allowlistedGithubHttps(target.cloneUrl);
  }
  const key = target.externalKey;
  if (typeof key === 'string' && key.startsWith('github:')) {
    return githubKeyToHttps(key);
  }
  throw new CheckoutError(
    'SCA source scan needs an allowlisted clone source (cloneUrl on github.com, or github:owner/repo). ' +
      'htmlUrl / url / git@ are refused so tenant-writable target metadata cannot drive scanner egress.',
  );
}

export function allowlistedGithubHttps(raw: string): string {
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
  if (parsed.hostname !== 'github.com' && parsed.hostname !== 'www.github.com') {
    throw new CheckoutError(`Refusing clone host '${parsed.hostname}' — only github.com is allowlisted`);
  }
  if (parsed.port && parsed.port !== '443') {
    throw new CheckoutError(`Refusing clone URL with non-default port: ${raw}`);
  }
  if (parsed.username || parsed.password) {
    throw new CheckoutError('Refusing clone URL that already embeds credentials');
  }
  const parts = parsed.pathname.replace(/\.git$/, '').split('/').filter(Boolean);
  if (parts.length !== 2 || !GITHUB_REPO.test(parts[0]) || !GITHUB_REPO.test(parts[1])) {
    throw new CheckoutError(`Refusing clone URL with an unexpected GitHub path: ${raw}`);
  }
  return `https://github.com/${parts[0]}/${parts[1]}.git`;
}

export function githubKeyToHttps(externalKey: string): string {
  const m = /^github:([\w.-]+)\/([\w.-]+)$/.exec(externalKey);
  if (!m) {
    throw new CheckoutError(`Refusing malformed github externalKey: ${externalKey}`);
  }
  return `https://github.com/${m[1]}/${m[2]}.git`;
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
          '(private GitHub assets would be missed; a public-only clone must not report empty success)',
      );
    }
    throw new CheckoutError(
      'Private repository requires a usable credentialRef (env:GITHUB_*). ' +
        'Refusing to clone unauthenticated.',
    );
  }
  return token;
}

export function withGithubToken(url: string, token: string): string {
  const parsed = new URL(url);
  parsed.username = 'x-access-token';
  parsed.password = token;
  return parsed.toString();
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
  exec: typeof execFileAsync = execFileAsync,
): Promise<void> {
  if (!SAFE_REF.test(ref)) {
    throw new CheckoutError(`Refusing to checkout unsafe git ref: ${ref}`);
  }
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== 'https:' || (parsed.hostname !== 'github.com' && parsed.hostname !== 'www.github.com')) {
      throw new CheckoutError(`Refusing to clone URL with unsupported scheme or host`);
    }
  } catch (err) {
    if (err instanceof CheckoutError) throw err;
    throw new CheckoutError(`Refusing unparseable clone URL`);
  }
  for (const args of gitCheckoutCommands(url, ref, dest)) {
    await exec('git', args, {
      timeout: 60_000,
      env: { ...process.env, GIT_TERMINAL_PROMPT: '0', GIT_ASKPASS: 'echo' },
    });
  }
}
