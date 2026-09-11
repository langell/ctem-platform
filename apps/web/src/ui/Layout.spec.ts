import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

describe('session chrome', () => {
  const layout = readFileSync(resolve('apps/web/src/ui/Layout.tsx'), 'utf8');
  const login = readFileSync(resolve('apps/web/src/pages/LoginPage.tsx'), 'utf8');

  it('shows role only and keeps org id in the tooltip', () => {
    expect(layout).toMatch(/title=\{session\.orgId\}/);
    expect(layout).toMatch(/\{session\.role\}/);
    expect(layout).not.toMatch(/orgId\.slice/);
    expect(layout).not.toMatch(/org \{session\.orgId/);
    expect(layout).toMatch(/className="brand">CTEM/);
  });

  it('uses Owner Dock: Ops then Admin, session in the footer, no top bar', () => {
    expect(layout).toMatch(/className="dock"/);
    expect(layout).toMatch(/className="bleed"/);
    expect(layout).not.toMatch(/topbar/);
    expect(layout).toMatch(/nav-group-label">\s*Ops/);
    expect(layout).toMatch(/nav-group-admin/);
    expect(layout).toMatch(/nav-group-label">\s*Admin/);
    expect(layout).toMatch(
      /<NavLink to="\/assets">Assets<\/NavLink>\s*<NavLink to="\/findings">Findings<\/NavLink>\s*<NavLink to="\/scans">Scan<\/NavLink>/,
    );
    expect(layout).toMatch(
      /<NavLink to="\/policies">Policies<\/NavLink>\s*<NavLink to="\/members">Members<\/NavLink>/,
    );
    expect(layout.indexOf('Ops')).toBeLessThan(layout.indexOf('Admin'));
    expect(layout.indexOf('to="/scans"')).toBeLessThan(layout.indexOf('to="/policies"'));
    expect(layout).toMatch(/className="session"/);
    expect(layout).toMatch(/Sign out/);
    expect(login).not.toMatch(/className="dock"/);
    expect(login).not.toMatch(/className="bleed"/);
  });
});
