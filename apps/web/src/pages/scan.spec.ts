import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const scan = readFileSync(resolve('apps/web/src/pages/ScanPage.tsx'), 'utf8');
const app = readFileSync(resolve('apps/web/src/App.tsx'), 'utf8');
const layout = readFileSync(resolve('apps/web/src/ui/Layout.tsx'), 'utf8');

describe('scan human path', () => {
  it('POSTs /v1/scans with optional comma-separated asset IDs and one submit button', () => {
    expect(scan).toMatch(/gatewayFetch<Scan>\('\/v1\/scans'/);
    expect(scan).toMatch(/method: 'POST'/);
    expect(scan).toMatch(/assetIds\s*\.split\(','\)/);
    expect(scan).toMatch(/assetSelector: ids\.length \? \{ assetIds: ids \} : \{\}/);
    expect(scan).toMatch(/placeholder="uuid, uuid"/);
    expect(scan).toMatch(/Asset IDs \(optional, comma-separated\)/);
    expect(scan.match(/type="submit"/g)?.length).toBe(1);
    expect(scan.match(/<button/g)?.length).toBe(1);
    expect(scan).toMatch(/Starting…/);
    expect(scan).toMatch(/Start scan/);
  });

  it('has no picker, poll, or history', () => {
    expect(scan.match(/<select/g)?.length).toBe(1);
    expect(scan).not.toMatch(/\/v1\/assets/);
    expect(scan).not.toMatch(/picker/i);
    expect(scan).not.toMatch(/useEffect/);
    expect(scan).not.toMatch(/setInterval/);
    expect(scan).not.toMatch(/poll/i);
    expect(scan).not.toMatch(/history/i);
    expect(scan).not.toMatch(/jobsTotal/);
    expect(scan).not.toMatch(/jobsCompleted/);
    expect(app).not.toMatch(/path="\/scans\//);
  });

  it('matches nav copy and drops the POST lecture', () => {
    expect(scan).toMatch(/<h1>Scan<\/h1>/);
    expect(scan).not.toMatch(/Kick a scan/);
    expect(scan).not.toMatch(/Dispatches/);
    expect(scan).not.toMatch(/POST \/v1\/scans/);
    expect(scan).toMatch(
      /Start a scan for this organization\. Leave asset IDs empty to include every in-scope asset\./,
    );
    expect(layout).toMatch(/<NavLink to="\/scans">Scan<\/NavLink>/);
  });

  it('humanizes scanner labels while keeping enum values', () => {
    expect(scan).toMatch(/SCANNER_TYPES\.map/);
    expect(scan).toMatch(/value=\{t\}/);
    expect(scan).toMatch(/\{humanize\(t\)\}/);
  });

  it('shows queued status as the card title and keeps the scan id muted', () => {
    expect(scan).toMatch(/<h2>\{humanize\(result\.status\)\}<\/h2>/);
    expect(scan).toMatch(/badge badge-muted/);
    expect(scan).toMatch(/humanize\(result\.scannerType\)/);
    expect(scan).toMatch(/className="small muted"/);
    expect(scan).toMatch(/<code>\{result\.id\}<\/code>/);
    expect(scan).toMatch(/GatewayError \? err\.message/);
  });

  it('takes org from the JWT and does not paste a token', () => {
    expect(scan).not.toMatch(/orgId/);
    expect(scan).not.toMatch(/<textarea/);
    expect(scan).not.toMatch(/Paste a JWT/);
    expect(layout).not.toMatch(/<select/);
  });
});
