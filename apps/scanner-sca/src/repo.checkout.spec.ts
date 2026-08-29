import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  CheckoutError,
  gitCheckoutCommands,
  resolveCheckout,
  resolveCloneUrl,
  resolveRef,
  shallowClone,
} from './repo.checkout';

afterEach(() => {
  delete process.env.GITHUB_TOKEN;
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

  it('ignores htmlUrl even when it points at GitHub — tenant-writable metadata is not egress', () => {
    expect(() =>
      resolveCloneUrl({ kind: 'repository', htmlUrl: 'https://github.com/acme/api' }),
    ).toThrow(CheckoutError);
  });

  it('refuses a non-github cloneUrl', () => {
    expect(() => resolveCloneUrl({ cloneUrl: 'https://evil.example/acme/api.git' })).toThrow(
      /only github.com is allowlisted/,
    );
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
