import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

/**
 * Login is JWT-only. Machine PATs authenticate as Authorization on the
 * gateway — the UI must not grow a PAT paste field.
 */
describe('login has no PAT paste field', () => {
  const login = readFileSync(resolve('apps/web/src/pages/LoginPage.tsx'), 'utf8');

  it('asks for a JWT and never prompts for a PAT', () => {
    expect(login).toMatch(/Present a bearer JWT from the IdP/);
    expect(login).toMatch(/placeholder="eyJ…"/);
    expect(login).toMatch(/<label>\s*JWT\s*<textarea/s);
    expect(login).toMatch(/Paste a JWT issued for your organization/);
    expect(login).not.toMatch(/\bPAT\b/);
    expect(login).not.toMatch(/ctem_pat_/);
    expect(login).not.toMatch(/personal access/i);
    expect(login).not.toMatch(/machine token/i);
  });
});
