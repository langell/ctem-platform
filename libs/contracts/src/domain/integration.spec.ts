import { describe, expect, it } from 'vitest';
import { ConnectGitHubRequest, IntegrationView } from './integration';

const TOKEN = 'ghp_super_secret_token_value';

describe('ConnectGitHubRequest', () => {
  it('accepts owner, ownerType, and token', () => {
    expect(ConnectGitHubRequest.parse({ owner: 'acme', ownerType: 'org', token: TOKEN })).toEqual({
      owner: 'acme',
      ownerType: 'org',
      token: TOKEN,
    });
  });

  it('rejects client-supplied org, provider, credentialRef, config, and base URL', () => {
    for (const extra of [
      { orgId: '00000000-0000-4000-8000-000000000001' },
      { provider: 'github' },
      { credentialRef: 'env:GITHUB_TOKEN' },
      { config: { owner: 'acme' } },
      { baseUrl: 'https://github.example.com' },
      { host: 'github.example.com' },
    ]) {
      const parsed = ConnectGitHubRequest.safeParse({
        owner: 'acme',
        ownerType: 'user',
        token: TOKEN,
        ...extra,
      });
      expect(parsed.success, JSON.stringify(extra)).toBe(false);
    }
  });
});

describe('IntegrationView', () => {
  it('drops a token and credentialRef if a caller attaches them', () => {
    const parsed = IntegrationView.safeParse({
      id: '00000000-0000-4000-8000-000000000010',
      provider: 'github',
      displayName: 'github:acme',
      owner: 'acme',
      ownerType: 'org',
      enabled: true,
      hasCredential: true,
      lastSyncAt: null,
      lastSyncError: null,
      token: TOKEN,
      credentialRef: `secret:00000000-0000-4000-8000-000000000010`,
      ciphertext: TOKEN,
    });
    expect(parsed.success).toBe(false);
    if (!parsed.success) {
      expect(JSON.stringify(parsed.error.issues)).not.toContain(TOKEN);
    }
  });
});
