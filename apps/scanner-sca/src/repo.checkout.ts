import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { Injectable } from '@nestjs/common';
import { rootLogger } from '@ctem/observability';
import type { ScanContext } from '@ctem/scanner-sdk';

const execFileAsync = promisify(execFile);

const SAFE_REF = /^[A-Za-z0-9._/-]+$/;
const SAFE_URL = /^(https?:\/\/|git@)/i;

export interface RepoCheckout {
  checkout(ctx: ScanContext): Promise<void>;
}

/**
 * Shallow-clones the job target into the worker's existing `ctx.workDir`.
 * The SDK already creates and deletes that directory — this does not invent
 * a second sandbox.
 */
@Injectable()
export class GitRepoCheckout implements RepoCheckout {
  private readonly log = rootLogger.child({ component: 'git-checkout' });

  async checkout(ctx: ScanContext): Promise<void> {
    const url = resolveCloneUrl(ctx.job.target);
    if (!url) {
      this.log.info({ assetId: ctx.job.assetId }, 'no clone URL on target — using workDir as-is');
      return;
    }
    const ref = resolveRef(ctx.job);
    this.log.info({ url, ref, workDir: ctx.workDir }, 'shallow checkout');
    await shallowClone(url, ref, ctx.workDir);
  }
}

export function resolveCloneUrl(target: Record<string, unknown>): string | null {
  const candidates = [target.cloneUrl, target.repoUrl, target.htmlUrl, target.url];
  for (const value of candidates) {
    if (typeof value === 'string' && value.length > 0) {
      const url = value.endsWith('.git') || value.startsWith('git@') ? value : `${value.replace(/\/$/, '')}.git`;
      return url;
    }
  }
  const key = target.externalKey;
  if (typeof key === 'string' && key.startsWith('github:')) {
    return `https://github.com/${key.slice('github:'.length)}.git`;
  }
  return null;
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
  if (!SAFE_URL.test(url)) {
    throw new Error(`Refusing to clone URL with unsupported scheme: ${url}`);
  }
  if (!SAFE_REF.test(ref)) {
    throw new Error(`Refusing to checkout unsafe git ref: ${ref}`);
  }
  for (const args of gitCheckoutCommands(url, ref, dest)) {
    await exec('git', args, {
      timeout: 60_000,
      env: { ...process.env, GIT_TERMINAL_PROMPT: '0', GIT_ASKPASS: 'echo' },
    });
  }
}
