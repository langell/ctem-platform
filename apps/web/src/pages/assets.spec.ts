import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const assets = readFileSync(resolve('apps/web/src/pages/AssetsPage.tsx'), 'utf8');
const app = readFileSync(resolve('apps/web/src/App.tsx'), 'utf8');

describe('assets human path', () => {
  it('keeps the six existing columns', () => {
    expect(assets).toMatch(/<th>Name<\/th>/);
    expect(assets).toMatch(/<th>Kind<\/th>/);
    expect(assets).toMatch(/<th>Source<\/th>/);
    expect(assets).toMatch(/<th>Exposure<\/th>/);
    expect(assets).toMatch(/<th>Criticality<\/th>/);
    expect(assets).toMatch(/<th>Owner<\/th>/);
    expect(assets.match(/<th>/g)?.length).toBe(6);
  });

  it('distinguishes loading vs empty vs error', () => {
    expect(assets).toMatch(/const \[loading, setLoading\] = useState\(true\)/);
    expect(assets).toMatch(/<SkeletonRows columns=\{6\} \/>/);
    expect(assets).toMatch(/className="empty-title">No assets in this organization/);
    expect(assets).toMatch(/Discovery connectors fill this list\./);
    expect(assets).toMatch(/className="banner error"/);
    expect(assets).toMatch(/GatewayError \? err\.message/);
    expect(assets).toMatch(/!loading && !error && items\.length === 0/);
    expect(assets).not.toMatch(/className="muted">\s*No assets in this organization/);
  });

  it('omits the assets count while loading or on error', () => {
    expect(assets).toMatch(
      /\{!loading && !error \? <p className="muted count">\{items\.length\} assets<\/p> : null\}/,
    );
  });

  it('always renders exposure and criticality as badges', () => {
    expect(assets).toMatch(/exposureBadgeClass\(a\.exposure\)/);
    expect(assets).toMatch(/severityBadgeClass\(a\.criticality\)/);
    expect(assets).not.toMatch(/a\.exposure === 'internet_facing'/);
  });

  it('keeps rows non-clickable with no asset detail route', () => {
    expect(assets).not.toMatch(/clickable/);
    expect(assets).not.toMatch(/onClick/);
    expect(assets).not.toMatch(/navigate\(/);
    expect(assets).not.toMatch(/\/assets\/\$\{/);
    expect(app).not.toMatch(/path="\/assets\/:id"/);
  });
});
