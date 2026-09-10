import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const members = readFileSync(resolve('apps/web/src/pages/MembersPage.tsx'), 'utf8');
const app = readFileSync(resolve('apps/web/src/App.tsx'), 'utf8');
const layout = readFileSync(resolve('apps/web/src/ui/Layout.tsx'), 'utf8');

const table = members.slice(members.indexOf('<table>'), members.indexOf('</table>'));
const form = members.slice(members.indexOf('<form'), members.indexOf('</form>'));

describe('members human path', () => {
  it('uses page-title and a loud Invite CTA after Policies in nav', () => {
    expect(members).toMatch(/<h1 className="page-title">Members<\/h1>/);
    expect(form).toMatch(/className="cta-loud"/);
    expect(form).toMatch(/\{busy \? 'Inviting…' : 'Invite'\}/);
    expect(layout).toMatch(
      /<NavLink to="\/policies">Policies<\/NavLink>\s*<NavLink to="\/members">Members<\/NavLink>/,
    );
    expect(app).toMatch(/path="\/members"/);
  });

  it('lists email/name, humanized role, Active/Disabled status, and actions', () => {
    expect(table).toMatch(/<th>Member<\/th>/);
    expect(table).toMatch(/<th>Role<\/th>/);
    expect(table).toMatch(/<th>Status<\/th>/);
    expect(table).toMatch(/<th>Actions<\/th>/);
    expect(table).toMatch(/\{m\.name \|\| m\.email\}/);
    expect(table).toMatch(/\{m\.email\}/);
    expect(table).toMatch(/humanize\(m\.role\)/);
    expect(members).toMatch(/badge-signal/);
    expect(table).toMatch(/roleBadgeClass\(m\.role\)/);
    expect(table).toMatch(/Disabled/);
    expect(table).toMatch(/Active/);
    expect(members).toMatch(/ROLES\.map/);
  });

  it('distinguishes loading vs empty vs error', () => {
    expect(members).toMatch(/const \[loading, setLoading\] = useState\(true\)/);
    expect(members).toMatch(/SkeletonRows/);
    expect(members).toMatch(/className="empty-title">No members in this organization/);
    expect(members).toMatch(/Invite someone to join this organization\./);
    expect(members).toMatch(/className="banner error"/);
    expect(members).toMatch(/GatewayError \? err\.message/);
    expect(members).toMatch(/!loading && items\.length === 0 && !error/);
    expect(members).toMatch(
      /\{!loading && !error \? <p className="muted count">\{items\.length\} members<\/p> : null\}/,
    );
  });

  it('invites with email + role and refreshes the list', () => {
    expect(form).toMatch(/type="email"/);
    expect(form).toMatch(/aria-label="Invite role"/);
    expect(members).toMatch(/method: 'POST'/);
    expect(members).toMatch(/gatewayFetch\('\/v1\/org\/members'/);
    expect(members).toMatch(/await reload\(\)/);
    expect(members).not.toMatch(/pending invite/i);
    expect(members).not.toMatch(/orgId/);
  });

  it('changes role with select + Save and surfaces API 4xx', () => {
    expect(table).toMatch(/aria-label=\{`Role for \$\{m\.email\}`\}/);
    expect(table).toMatch(/onClick=\{\(\) => void onSaveRole\(m\)\}/);
    expect(table).toMatch(/\bSave\b/);
    expect(members).toMatch(/method: 'PATCH'/);
    expect(members).toMatch(/\/v1\/org\/members\/\$\{member\.userId\}\/role/);
    expect(members).toMatch(/Failed to change role/);
    expect(members).toMatch(/GatewayError \? err\.message/);
  });

  it('disables only after a confirm dialog then DELETE', () => {
    expect(members).toMatch(/<dialog/);
    expect(members).toMatch(/Disable member\?/);
    expect(members).toMatch(/Disable member/);
    expect(members).toMatch(/method: 'DELETE'/);
    expect(members).toMatch(/\/v1\/org\/members\/\$\{target\.userId\}/);
    expect(members).toMatch(/setPendingDisable/);
    expect(members).not.toMatch(/window\.confirm/);
  });

  it('hides write controls without member:manage and never sends org', () => {
    expect(members).toMatch(/permissions\.includes\('member:manage'\)/);
    expect(members).toMatch(/This role can read members\. Managing requires member:manage\./);
    expect(members).toMatch(/canManage \? \(/);
    expect(members).not.toMatch(/orgId/);
    expect(members).not.toMatch(/keycloak/i);
    expect(members).not.toMatch(/SCIM/);
    expect(members).not.toMatch(/password reset/i);
    expect(app).not.toMatch(/path="\/members\//);
  });
});
