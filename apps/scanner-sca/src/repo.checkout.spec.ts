import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  CheckoutError,
  githubHttpExtraHeader,
  gitlabHttpExtraHeader,
  gitCheckoutCommands,
  resolveCheckout,
  resolveCloneUrl,
  resolveRef,
  shallowClone,
} from './repo.checkout';

afterEach(() => {
  delete process.env.GITHUB_TOKEN;
  delete process.env.GITLAB_TOKEN;
});

describe('resolveCloneUrl', () => {
  it('synthesizes a GitHub URL from github: externalKey', () => {
    expect(resolveCloneUrl({ kind: 'repository', externalKey: 'github:acme/api' })).toBe(
      'https://github.com/acme/api.git',
    );
  });

  it('accepts an allowlisted cloneUrl on github.com', () => {
    expect(resolveCloneUrl({ cloneUrl: 'https://github.com/acme/api.git' })).toBe(
      'https://github.com/acme/api.git',
    );
  });

  it('synthesizes a GitLab URL from gitlab: externalKey, including nested groups', () => {
    expect(resolveCloneUrl({ kind: 'repository', externalKey: 'gitlab:acme/api' })).toBe(
      'https://gitlab.com/acme/api.git',
    );
    expect(resolveCloneUrl({ kind: 'repository', externalKey: 'gitlab:acme/platform/api' })).toBe(
      'https://gitlab.com/acme/platform/api.git',
    );
  });

  it('accepts an allowlisted cloneUrl on gitlab.com', () => {
    expect(resolveCloneUrl({ cloneUrl: 'https://gitlab.com/acme/platform/api.git' })).toBe(
      'https://gitlab.com/acme/platform/api.git',
    );
  });

  it('proceeds when cloneUrl and a github:/gitlab: key canonicalize to the same host+path', () => {
    expect(
      resolveCloneUrl({
        kind: 'repository',
        externalKey: 'github:acme/api',
        cloneUrl: 'https://github.com/acme/api.git',
      }),
    ).toBe('https://github.com/acme/api.git');
    expect(
      resolveCloneUrl({
        kind: 'repository',
        externalKey: 'github:acme/api',
        cloneUrl: 'https://www.github.com/acme/api',
      }),
    ).toBe('https://github.com/acme/api.git');
    expect(
      resolveCloneUrl({
        kind: 'repository',
        externalKey: 'gitlab:acme/platform/api',
        cloneUrl: 'https://gitlab.com/acme/platform/api.git',
      }),
    ).toBe('https://gitlab.com/acme/platform/api.git');
  });

  it('fails closed when cloneUrl points at a different owner/repo than the github:/gitlab: key', () => {
    expect(() =>
      resolveCloneUrl({
        kind: 'repository',
        externalKey: 'github:acme/api',
        cloneUrl: 'https://github.com/evil/other.git',
      }),
    ).toThrow(/does not match asset identity 'github:acme\/api'/);
    expect(() =>
      resolveCloneUrl({
        kind: 'repository',
        externalKey: 'gitlab:acme/platform/api',
        cloneUrl: 'https://gitlab.com/acme/other.git',
      }),
    ).toThrow(/does not match asset identity/);
    expect(() =>
      resolveCloneUrl({
        kind: 'repository',
        externalKey: 'github:acme/api',
        cloneUrl: 'https://gitlab.com/acme/api.git',
      }),
    ).toThrow(/does not match asset identity/);
  });

  it('ignores htmlUrl even when it points at GitHub — tenant-writable metadata is not egress', () => {
    expect(() =>
      resolveCloneUrl({ kind: 'repository', htmlUrl: 'https://github.com/acme/api' }),
    ).toThrow(CheckoutError);
  });

  it('refuses a non-allowlisted cloneUrl host', () => {
    expect(() => resolveCloneUrl({ cloneUrl: 'https://evil.example/acme/api.git' })).toThrow(
      /only github.com and gitlab.com are allowlisted/,
    );
    expect(() => resolveCloneUrl({ cloneUrl: 'https://gitlab.example.com/acme/api.git' })).toThrow(
      /only github.com and gitlab.com are allowlisted/,
    );
    expect(() => resolveCloneUrl({ cloneUrl: 'https://self-hosted.gitlab.com/acme/api.git' })).toThrow(
      /allowlisted/,
    );
  });

  it('refuses git@ GitLab URLs and tenant-writable htmlUrl', () => {
    expect(() => resolveCloneUrl({ cloneUrl: 'git@gitlab.com:acme/api.git' })).toThrow(/git@/);
    expect(() =>
      resolveCloneUrl({ kind: 'repository', htmlUrl: 'https://gitlab.com/acme/api' }),
    ).toThrow(CheckoutError);
  });

  it('refuses git@ URLs', () => {
    expect(() => resolveCloneUrl({ cloneUrl: 'git@github.com:acme/api.git' })).toThrow(/git@/);
  });

  it('refuses arbitrary url / repoUrl fields', () => {
    expect(() => resolveCloneUrl({ url: 'https://github.com/acme/api' })).toThrow(/allowlisted clone source/);
    expect(() => resolveCloneUrl({ repoUrl: 'https://github.com/acme/api.git' })).toThrow(
      /allowlisted clone source/,
    );
  });

  it('throws when the target has no allowlisted source', () => {
    expect(() => resolveCloneUrl({ kind: 'container_image', externalKey: 'image:nginx' })).toThrow(
      CheckoutError,
    );
  });
});

describe('resolveCheckout credentials', () => {
  const githubTarget = { kind: 'repository', externalKey: 'github:acme/api' };

  it('clones public GitHub without a credential', () => {
    expect(resolveCheckout({ target: githubTarget, credentialRef: null })).toEqual({
      url: 'https://github.com/acme/api.git',
    });
  });

  it('fails closed when the target is private and credentialRef is unset', () => {
    expect(() =>
      resolveCheckout({ target: { ...githubTarget, private: true }, credentialRef: null }),
    ).toThrow(/Private repository requires a usable credentialRef/);
  });

  it('fails closed when credentialRef is set but the env var is empty', () => {
    expect(() =>
      resolveCheckout({ target: githubTarget, credentialRef: 'env:GITHUB_TOKEN' }),
    ).toThrow(/cannot be used/);
  });

  it('fails closed on a non-allowlisted credentialRef', () => {
    expect(() =>
      resolveCheckout({ target: githubTarget, credentialRef: 'env:DATABASE_URL' }),
    ).toThrow(/not allowlisted/);
  });

  it('uses an allowlisted GITHUB_* token when present', () => {
    process.env.GITHUB_TOKEN = 'ghp_test';
    expect(resolveCheckout({ target: githubTarget, credentialRef: 'env:GITHUB_TOKEN' })).toEqual({
      url: 'https://github.com/acme/api.git',
      token: 'ghp_test',
    });
  });

  it('fails closed on a private GitLab target without a usable credential', () => {
    expect(() =>
      resolveCheckout({
        target: { kind: 'repository', externalKey: 'gitlab:acme/api', private: true },
        credentialRef: null,
      }),
    ).toThrow(/Private repository requires a usable credentialRef/);
  });

  it('uses an allowlisted GITLAB_* token for a GitLab target', () => {
    process.env.GITLAB_TOKEN = 'glpat_test';
    expect(
      resolveCheckout({
        target: { kind: 'repository', externalKey: 'gitlab:acme/api' },
        credentialRef: 'env:GITLAB_TOKEN',
      }),
    ).toEqual({
      url: 'https://gitlab.com/acme/api.git',
      token: 'glpat_test',
    });
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
    await shallowClone('https://github.com/acme/api.git', 'main', '/tmp/work', { exec: exec as never });
    expect(exec.mock.calls.map((c) => c[1])).toEqual(
      gitCheckoutCommands('https://github.com/acme/api.git', 'main', '/tmp/work'),
    );
  });

  it('passes the PAT as http.extraHeader and never puts it on the remote', async () => {
    const token = 'ghp_not_for_remote_url';
    const exec = vi.fn(async () => ({ stdout: '', stderr: '' }));
    await shallowClone('https://github.com/acme/api.git', 'main', '/tmp/work', {
      exec: exec as never,
      token,
    });

    const argLists = exec.mock.calls.map((c) => c[1] as string[]);
    expect(argLists.some((args) => args.includes('https://github.com/acme/api.git'))).toBe(true);
    expect(JSON.stringify(argLists)).not.toContain(token);
    expect(JSON.stringify(argLists)).not.toContain('x-access-token');

    const envs = exec.mock.calls.map((c) => c[2] as { env?: NodeJS.ProcessEnv });
    expect(envs.every((opts) => opts.env?.GIT_CONFIG_KEY_0 === 'http.extraHeader')).toBe(true);
    expect(envs.every((opts) => opts.env?.GIT_CONFIG_VALUE_0 === githubHttpExtraHeader(token))).toBe(true);
    expect(envs.every((opts) => !opts.env?.GIT_CONFIG_VALUE_0?.includes(token))).toBe(true);
  });

  it('passes a GitLab PAT as extraHeader and never embeds it in the remote URL', async () => {
    const token = 'glpat_not_for_remote_url';
    const exec = vi.fn(async () => ({ stdout: '', stderr: '' }));
    await shallowClone('https://gitlab.com/acme/api.git', 'main', '/tmp/work', {
      exec: exec as never,
      token,
    });

    const argLists = exec.mock.calls.map((c) => c[1] as string[]);
    expect(argLists.some((args) => args.includes('https://gitlab.com/acme/api.git'))).toBe(true);
    expect(JSON.stringify(argLists)).not.toContain(token);
    expect(JSON.stringify(argLists)).not.toContain('oauth2');
    expect(JSON.stringify(argLists)).not.toContain('glpat_');

    const envs = exec.mock.calls.map((c) => c[2] as { env?: NodeJS.ProcessEnv });
    expect(envs.every((opts) => opts.env?.GIT_CONFIG_KEY_0 === 'http.extraHeader')).toBe(true);
    expect(envs.every((opts) => opts.env?.GIT_CONFIG_VALUE_0 === gitlabHttpExtraHeader(token))).toBe(true);
    expect(envs.every((opts) => !opts.env?.GIT_CONFIG_VALUE_0?.includes(token))).toBe(true);
  });

  it('refuses a remote URL that already embeds credentials', async () => {
    await expect(
      shallowClone('https://x-access-token:ghp_leak@github.com/acme/api.git', 'main', '/tmp/w'),
    ).rejects.toThrow(/embeds credentials/);
    await expect(
      shallowClone('https://oauth2:glpat_leak@gitlab.com/acme/api.git', 'main', '/tmp/w'),
    ).rejects.toThrow(/embeds credentials/);
  });

  it('allows a gitlab.com origin and refuses a self-hosted host', async () => {
    const exec = vi.fn(async () => ({ stdout: '', stderr: '' }));
    await shallowClone('https://gitlab.com/acme/api.git', 'main', '/tmp/work', { exec: exec as never });
    expect(exec).toHaveBeenCalled();
    await expect(shallowClone('https://gitlab.example.com/acme/api.git', 'main', '/tmp/w')).rejects.toThrow(
      /unsupported scheme or host/,
    );
  });

  it('refuses flag-like refs', async () => {
    await expect(shallowClone('https://github.com/acme/api.git', '--upload-pack=evil', '/tmp/w')).rejects.toThrow(
      /unsafe git ref/,
    );
  });
});
