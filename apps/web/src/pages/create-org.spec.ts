import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

describe('create-org screen', () => {
  const page = readFileSync(resolve('apps/web/src/pages/CreateOrgPage.tsx'), 'utf8');
  const callback = readFileSync(resolve('apps/web/src/pages/CallbackPage.tsx'), 'utf8');

  it('uses the login card and posts only name and slug when the session is No organization', () => {
    expect(page).toMatch(/className="login"/);
    expect(page).toMatch(/className="card login-card"/);
    expect(page).toMatch(/className="login-brand">CTEM/);
    expect(page).toMatch(/Create your organization/);
    expect(page).toMatch(/Create organization/);
    expect(page).toMatch(/isNoOrganizationError/);
    expect(page).toMatch(/gatewayFetch<CreatedOrg>\('\/v1\/orgs'/);
    expect(page).toMatch(/name: name\.trim\(\)/);
    expect(page).toMatch(/slug: slug\.trim\(\)\.toLowerCase\(\)/);
    expect(page).toMatch(/navigate\('\/findings'/);
    expect(page).toMatch(/err instanceof GatewayError && err\.status === 409/);
    expect(page).toMatch(/gatewayFetch<Session>\('\/v1\/session'\)/);
    expect(page).toMatch(/navigate\('\/findings', \{ replace: true \}\)/);
    expect(page).toMatch(/disabled=\{busy\}/);
    expect(callback).toMatch(/isNoOrganizationError/);
    expect(callback).toMatch(/navigate\('\/create-org'/);
    expect(page).not.toMatch(/type=["']password["']/);
    expect(page).not.toMatch(/orgId/);
    expect(page).not.toMatch(/org_id/);
    expect(page).not.toMatch(/\brole\b/);
    expect(page).not.toMatch(/userId/);
    expect(page).not.toMatch(/\bplan\b/);
    expect(page).not.toMatch(/\bPAT\b/);
  });
});
