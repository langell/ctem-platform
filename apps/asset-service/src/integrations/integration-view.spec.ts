import { describe, expect, it } from 'vitest';
import { toIntegrationView } from './integration-view';

const TOKEN = 'ghs_e2e_stub_token_do_not_leak';
const ID = '00000000-0000-4000-8000-000000000010';

describe('toIntegrationView', () => {
  it('never includes the token, credentialRef, or secret fields', () => {
    const view = toIntegrationView({
      id: ID,
      provider: 'github',
      displayName: 'github:acme',
      config: { owner: 'acme', ownerType: 'org' },
      credentialRef: `secret:${ID}`,
      enabled: true,
      lastSyncAt: new Date('2026-10-05T18:00:00.000Z'),
      lastSyncError: `GitHub API returned 500 (${TOKEN})`,
      secret: { integrationId: ID },
    });
    const blob = JSON.stringify(view);
    expect(blob).not.toContain(TOKEN);
    expect(blob).not.toContain('credentialRef');
    expect(blob).not.toContain('ciphertext');
    expect(view.lastSyncError).not.toContain(TOKEN);
    expect(view.hasCredential).toBe(true);
    expect(view.owner).toBe('acme');
    expect(view.ownerType).toBe('org');
    expect(Object.keys(view).sort()).toEqual(
      [
        'displayName',
        'enabled',
        'hasCredential',
        'id',
        'lastSyncAt',
        'lastSyncError',
        'owner',
        'ownerType',
        'provider',
      ].sort(),
    );
  });
});
