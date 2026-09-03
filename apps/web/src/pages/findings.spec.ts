import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const findings = readFileSync(resolve('apps/web/src/pages/FindingsPage.tsx'), 'utf8');
const detail = readFileSync(resolve('apps/web/src/pages/FindingDetailPage.tsx'), 'utf8');
const assets = readFileSync(resolve('apps/web/src/pages/AssetsPage.tsx'), 'utf8');
const policies = readFileSync(resolve('apps/web/src/pages/PoliciesPage.tsx'), 'utf8');

describe('findings list human path', () => {
  it('keeps the six existing columns', () => {
    expect(findings).toMatch(/<th>Title<\/th>/);
    expect(findings).toMatch(/<th>Severity<\/th>/);
    expect(findings).toMatch(/<th className="num">Risk<\/th>/);
    expect(findings).toMatch(/<th>State<\/th>/);
    expect(findings).toMatch(/<th>Validation<\/th>/);
    expect(findings).toMatch(/<th>Scanner<\/th>/);
  });

  it('distinguishes loading vs empty vs error', () => {
    expect(findings).toMatch(/const \[loading, setLoading\] = useState\(true\)/);
    expect(findings).toMatch(/<SkeletonRows columns=\{6\} \/>/);
    expect(findings).toMatch(/No findings yet/);
    expect(findings).toMatch(/Run a scan from Scan, or wait for the next scheduled job/);
    expect(findings).toMatch(/className="banner error"/);
    expect(findings).toMatch(/GatewayError \? err\.message/);
    expect(findings).toMatch(/!loading && !error && items\.length === 0/);
    expect(findings).not.toMatch(/No findings in this organization/);
    expect(assets).toMatch(/const \[loading, setLoading\] = useState\(true\)/);
    expect(assets).toMatch(/<SkeletonRows columns=\{6\} \/>/);
    expect(assets).toMatch(/!loading && !error && items\.length === 0/);
    expect(policies).toMatch(/const \[loading, setLoading\] = useState\(true\)/);
    expect(policies).toMatch(/SkeletonRows/);
    expect(policies).toMatch(/!loading && items\.length === 0 && !error/);
  });

  it('omits the findings count while loading', () => {
    expect(findings).toMatch(/\{!loading \? <p className="muted count">\{items\.length\} findings<\/p> : null\}/);
  });

  it('whole row clicks through to detail', () => {
    expect(findings).toMatch(/onClick=\{\(\) => navigate\(`\/findings\/\$\{f\.id\}`\)\}/);
    expect(findings).toMatch(/className="clickable"/);
    expect(findings).toMatch(/<Link to=\{`\/findings\/\$\{f\.id\}`\}>/);
  });
});

describe('finding detail human path', () => {
  it('loads with title and two card skeletons, not a lone Loading…', () => {
    expect(detail).toMatch(/className="skeleton skeleton-title"/);
    expect(detail).toMatch(/className="card skeleton skeleton-card"/);
    expect(detail.match(/skeleton-card/g)?.length).toBe(2);
    expect(detail).not.toMatch(/Loading…/);
    expect(detail).toMatch(/<Link to="\/findings">Findings<\/Link>/);
  });

  it('uses chips and a contribution bar instead of dl / toFixed(3)', () => {
    expect(detail).toMatch(/className="chips"/);
    expect(detail).not.toMatch(/<dl/);
    expect(detail).toMatch(/contrib-bar/);
    expect(detail).not.toMatch(/toFixed\(3\)/);
    expect(detail).toMatch(/className=\{`score \$\{scoreClass\(risk\.score\)\}`\}/);
  });
});
