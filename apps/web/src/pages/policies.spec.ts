import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const policies = readFileSync(resolve('apps/web/src/pages/PoliciesPage.tsx'), 'utf8');
const app = readFileSync(resolve('apps/web/src/App.tsx'), 'utf8');

const table = policies.slice(policies.indexOf('<table>'), policies.indexOf('</table>'));
const form = policies.slice(policies.indexOf('<form'), policies.indexOf('</form>'));

describe('policies human path', () => {
  it('distinguishes loading vs empty', () => {
    expect(policies).toMatch(/const \[loading, setLoading\] = useState\(true\)/);
    expect(policies).toMatch(/SkeletonRows/);
    expect(policies).toMatch(/className="empty-title">No rules yet/);
    expect(policies).toMatch(/Create a rule to notify, ticket, or fail a build\./);
    expect(policies).toMatch(/!loading && items\.length === 0 && !error/);
    expect(policies).not.toMatch(/No policies in this organization/);
    expect(policies).toMatch(
      /\{!loading && !error \? <p className="muted count">\{items\.length\} rules<\/p> : null\}/,
    );
  });

  it('shows Enabled as a badge, not a table PATCH', () => {
    expect(table).toMatch(/badge badge-ok/);
    expect(table).toMatch(/badge badge-muted/);
    expect(table).toMatch(/Enabled/);
    expect(table).toMatch(/Disabled/);
    expect(table).not.toMatch(/yes/);
    expect(table).not.toMatch(/<input/);
    expect(table).not.toMatch(/type="checkbox"/);
    expect(table).not.toMatch(/enabled:/);
    expect(table).not.toMatch(/method: 'PATCH'/);
    expect(policies).toMatch(/body: \{ priority: neighbor\.priority \}/);
    expect(policies).not.toMatch(/type=["']checkbox["'][^>]*>[\s\S]*Enabled[\s\S]*<\/td>/);
  });

  it('keeps condition fields and action combos unchanged', () => {
    expect(form).toMatch(/Severity at least/);
    expect(form).toMatch(/Minimum risk score/);
    expect(form).toMatch(/KEV only/);
    expect(form).toMatch(/<option value="">Any<\/option>/);
    expect(form).toMatch(/SEVERITIES\.map/);
    expect(form).toMatch(/<option value="notify">Notify \(Slack\)<\/option>/);
    expect(form).toMatch(/<option value="ticket">Ticket \(Jira\)<\/option>/);
    expect(form).toMatch(/<option value="fail_build">Fail build \(CI GET\)<\/option>/);
    expect(form).toMatch(/<option value="notify,ticket">Notify and ticket<\/option>/);
    expect(form).toMatch(/<option value="notify,fail_build">Notify and fail build<\/option>/);
    expect(form).toMatch(/<option value="ticket,fail_build">Ticket and fail build<\/option>/);
    expect(form).toMatch(
      /<option value="notify,ticket,fail_build">Notify, ticket, and fail build<\/option>/,
    );
    expect(form).not.toMatch(/<option value="block_deploy"/);
    expect(form).not.toMatch(/minEpss/);
    expect(form).not.toMatch(/requireFixAvailable/);
    expect(form).toMatch(/block-deploy and tenant webhook\/Jira URLs are out of this slice/);
  });

  it('humanizes the action column and marks the editing row', () => {
    expect(table).toMatch(/p\.actions\.map\(humanize\)\.join\(', '\)/);
    expect(policies).toMatch(/className=\{editingId === p\.id \? 'editing' : undefined\}/);
    expect(form).toMatch(/className="form-actions"/);
    expect(form).toMatch(/Cancel edit/);
    expect(form).toMatch(/Update rule/);
    expect(policies).not.toMatch(/modal/i);
  });

  it('drops JWT/org/GitHub lecture from the page face and keeps the read-only line', () => {
    expect(policies).toMatch(/Ordered rules\. Lower priority runs first; the first match wins\./);
    expect(policies).not.toMatch(/GitHub Check/);
    expect(policies).not.toMatch(/organization on the token/);
    expect(policies).toMatch(/This role can read policies\. Writing requires policy:write\./);
    expect(policies).not.toMatch(/orgId/);
    expect(app).not.toMatch(/path="\/policies\//);
  });
});
