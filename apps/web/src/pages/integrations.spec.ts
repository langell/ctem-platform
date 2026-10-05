import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const page = readFileSync(resolve('apps/web/src/pages/IntegrationsPage.tsx'), 'utf8');

describe('connect github screen', () => {
  it('uses a password field and clears the token on submit', () => {
    expect(page).toMatch(/<h1 className="page-title">Connect GitHub<\/h1>/);
    expect(page).toMatch(/type="password"/);
    expect(page).toMatch(/const submitted = token/);
    expect(page).toMatch(/setToken\(''\)/);
    expect(page).toMatch(/integration:manage/);
    expect(page).toMatch(/\/v1\/integrations\/github/);
    expect(page).not.toMatch(/credentialRef/);
    expect(page).not.toMatch(/GITHUB_API_URL/);
  });
});
