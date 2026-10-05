import { describe, expect, it } from 'vitest';
import { scrubSyncError, scrubText } from './scrub';

const TOKEN = 'ghs_e2e_stub_token_do_not_leak';

describe('scrubText', () => {
  it('removes the pasted token and token-shaped values', () => {
    const message = scrubText(`GitHub API returned 500 for /user (${TOKEN})`, TOKEN);
    expect(message).not.toContain(TOKEN);
    expect(message).toContain('500');
    expect(scrubText('Authorization: Bearer ghp_abcdefghijklmnopqrstuvwxyz')).not.toContain('ghp_');
  });

  it('keeps allowlist and status text that has no secret', () => {
    expect(scrubSyncError(new Error('credentialRef env:DATABASE_URL is not allowlisted'))).toMatch(
      /not allowlisted/,
    );
    expect(
      scrubSyncError(new Error('GitHub API returned 500 for /orgs/acme/repos (page 1)')),
    ).toMatch(/500/);
  });

  it('does not echo the token when the error is not an Error', () => {
    expect(scrubSyncError(TOKEN, TOKEN)).not.toContain(TOKEN);
  });
});
