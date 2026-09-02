import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

/**
 * Browser login is OIDC redirect + PKCE. Machine PATs authenticate as
 * Authorization on the gateway — the UI must not grow a password or PAT field.
 */
describe('login has no password or PAT paste field', () => {
  const login = readFileSync(resolve('apps/web/src/pages/LoginPage.tsx'), 'utf8');
  const callback = readFileSync(resolve('apps/web/src/pages/CallbackPage.tsx'), 'utf8');

  it('starts Keycloak authorize and never prompts for a password, JWT paste, or PAT', () => {
    expect(login).toMatch(/Sign in with Keycloak/);
    expect(login).toMatch(/beginAuthorization/);
    expect(login).toMatch(/compose Keycloak/);
    expect(callback).toMatch(/completeAuthorization/);
    expect(callback).toMatch(/issued access-token JWT/);
    expect(callback).toMatch(/history\.replaceState/);
    expect(callback).toMatch(/readStoredAccessJwt/);
    expect(callback).not.toMatch(/catch \(err\) \{\s*tokenStore\(\)\.clear\(\)/);
    for (const source of [login, callback]) {
      expect(source).not.toMatch(/type=["']password["']/);
      expect(source).not.toMatch(/<textarea/);
      expect(source).not.toMatch(/placeholder="eyJ/);
      expect(source).not.toMatch(/Paste a JWT/);
      expect(source).not.toMatch(/\bPAT\b/);
      expect(source).not.toMatch(/ctem_pat_/);
      expect(source).not.toMatch(/personal access/i);
      expect(source).not.toMatch(/machine token/i);
    }
  });
});
