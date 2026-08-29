import { describe, expect, it, vi } from 'vitest';
import {
  gitCheckoutCommands,
  resolveCloneUrl,
  resolveRef,
  shallowClone,
} from './repo.checkout';

describe('resolveCloneUrl', () => {
  it('prefers htmlUrl from GitHub discovery attributes', () => {
    expect(resolveCloneUrl({ htmlUrl: 'https://github.com/acme/api', externalKey: 'github:acme/api' })).toBe(
      'https://github.com/acme/api.git',
    );
  });

  it('synthesizes a GitHub URL from externalKey', () => {
    expect(resolveCloneUrl({ kind: 'repository', externalKey: 'github:acme/api' })).toBe(
      'https://github.com/acme/api.git',
    );
  });

  it('returns null when the target is not a repo', () => {
    expect(resolveCloneUrl({ kind: 'container_image', externalKey: 'image:nginx' })).toBeNull();
  });
});

describe('resolveRef', () => {
  it('pins options.ref over the default branch', () => {
    expect(
      resolveRef({
        options: { ref: 'abc123' },
        target: { defaultBranch: 'main' },
      }),
    ).toBe('abc123');
  });

  it('falls back to HEAD', () => {
    expect(resolveRef({ options: {}, target: {} })).toBe('HEAD');
  });
});

describe('shallowClone', () => {
  it('runs init/fetch/checkout against the existing workDir', async () => {
    const exec = vi.fn(async () => ({ stdout: '', stderr: '' }));
    await shallowClone('https://github.com/acme/api.git', 'main', '/tmp/work', exec as never);
    expect(exec.mock.calls.map((c) => c[1])).toEqual(
      gitCheckoutCommands('https://github.com/acme/api.git', 'main', '/tmp/work'),
    );
  });

  it('refuses flag-like refs', async () => {
    await expect(shallowClone('https://github.com/acme/api.git', '--upload-pack=evil', '/tmp/w')).rejects.toThrow(
      /unsafe git ref/,
    );
  });
});
