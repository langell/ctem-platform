import { describe, expect, it } from 'vitest';
import { SbomParser } from './sbom.parser';
import type { ArtifactStore } from '@ctem/storage';

const parser = new SbomParser(null as unknown as ArtifactStore);

describe('SbomParser.parseCycloneDx', () => {
  const doc = {
    bomFormat: 'CycloneDX',
    metadata: { component: { 'bom-ref': 'root' } },
    components: [
      {
        'bom-ref': 'pkg:npm/express@4.17.1',
        purl: 'pkg:npm/express@4.17.1',
        name: 'express',
        version: '4.17.1',
        licenses: [{ license: { id: 'MIT' } }],
      },
      {
        'bom-ref': 'pkg:npm/qs@6.7.0',
        purl: 'pkg:npm/qs@6.7.0',
        name: 'qs',
        version: '6.7.0',
      },
      {
        purl: 'pkg:pypi/requests@2.25.0',
        name: 'requests',
        version: '2.25.0',
      },
      {
        name: 'inhouse-lib',
        version: '1.0.0',
      },
    ],
    dependencies: [
      { ref: 'root', dependsOn: ['pkg:npm/express@4.17.1'] },
      { ref: 'pkg:npm/express@4.17.1', dependsOn: ['pkg:npm/qs@6.7.0'] },
    ],
  };

  it('marks only root dependencies as direct', () => {
    const byName = Object.fromEntries(parser.parseCycloneDx(doc).map((c) => [c.name, c]));
    expect(byName.express.direct).toBe(true);
    expect(byName.qs.direct).toBe(false);
  });

  it('normalizes purl types to OSV ecosystem names', () => {
    const byName = Object.fromEntries(parser.parseCycloneDx(doc).map((c) => [c.name, c]));
    expect(byName.express.ecosystem).toBe('npm');
    expect(byName.requests.ecosystem).toBe('PyPI');
    expect(byName['inhouse-lib'].ecosystem).toBe('unknown');
  });

  it('synthesizes a purl when the component has none', () => {
    const byName = Object.fromEntries(parser.parseCycloneDx(doc).map((c) => [c.name, c]));
    expect(byName['inhouse-lib'].purl).toBe('pkg:generic/inhouse-lib@1.0.0');
  });

  it('collects license ids', () => {
    const byName = Object.fromEntries(parser.parseCycloneDx(doc).map((c) => [c.name, c]));
    expect(byName.express.licenses).toEqual(['MIT']);
  });

  it('handles a document without a dependency graph', () => {
    const components = parser.parseCycloneDx({ components: doc.components });
    expect(components).toHaveLength(4);
    expect(components.every((c) => c.direct === false)).toBe(true);
  });
});
