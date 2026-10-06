import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { loadEnv, resetEnvCache } from '@ctem/config';
import { githubApiUrl } from './github-api';

const STUB = 'http://127.0.0.1:4019';

afterEach(() => {
  resetEnvCache();
});

describe('githubApiUrl', () => {
  it('accepts the stub origin only when the schema-validated URL is that origin', () => {
    const env = loadEnv({ NODE_ENV: 'development', CTEM_GITHUB_API_URL: STUB });
    expect(githubApiUrl('/user', env)).toBe(`${STUB}/user`);
    expect(() => githubApiUrl('https://api.github.com/user', env)).toThrow(
      /Refusing GitHub API host/,
    );
    expect(() => githubApiUrl('https://evil.example/user', env)).toThrow(
      /Refusing GitHub API host/,
    );
  });

  it('refuses the stub host when the validated URL is api.github.com', () => {
    const env = loadEnv({ NODE_ENV: 'development', CTEM_GITHUB_API_URL: 'https://api.github.com' });
    expect(githubApiUrl('/orgs/acme', env)).toBe('https://api.github.com/orgs/acme');
    expect(() => githubApiUrl(`${STUB}/user`, env)).toThrow(/Refusing GitHub API host/);
  });

  it('does not special-case a stub host or NODE_ENV in connector code', () => {
    const connector = readFileSync(
      resolve('apps/asset-service/src/connectors/github.connector.ts'),
      'utf8',
    );
    const api = readFileSync(resolve('apps/asset-service/src/connectors/github-api.ts'), 'utf8');
    const combined = `${connector}\n${api}`;
    expect(combined).not.toMatch(/127\.0\.0\.1/);
    expect(combined).not.toMatch(/NODE_ENV/);
    expect(combined).not.toMatch(/github-stub/);
  });
});
