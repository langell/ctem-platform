import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { parseCargoLock } from './cargo';
import { parseComposerLock } from './composer';
import { parseGemfileLock } from './gem';
import { parseGoModules } from './golang';
import { parseGradleLockfile, parsePomXml } from './maven';
import { npmParser, parseNpmLock } from './npm';
import { parseCsproj, parsePackagesLock } from './nuget';
import { parseRequirementsTxt } from './pip';
import { parsePnpmLock, splitPnpmKey } from './pnpm';
import { parsePoetryLock } from './poetry';
import { filesToRead, LockfileResolutionError, resolveLockfiles } from './resolve';
import { parseYarnClassic, yarnParser } from './yarn';

const FIX = join(__dirname, '__fixtures__');

function load(...parts: string[]): string {
  return readFileSync(join(FIX, ...parts), 'utf8');
}

function byName(components: Array<{ name: string }>) {
  return Object.fromEntries(components.map((c) => [c.name, c]));
}

describe('npm package-lock.json', () => {
  it('parses v3 lockfiles with direct vs transitive paths', () => {
    const components = parseNpmLock({
      relPath: 'package-lock.json',
      content: load('npm', 'package-lock.json'),
      companions: {},
    });
    const map = byName(components);
    expect(map.express).toMatchObject({
      version: '4.17.1',
      ecosystem: 'npm',
      direct: true,
      dependencyPath: ['express'],
      purl: 'pkg:npm/express@4.17.1',
      manifestPath: 'package-lock.json',
    });
    expect(map.qs).toMatchObject({
      version: '6.7.0',
      direct: false,
      dependencyPath: ['express', 'qs'],
    });
    expect(map['local-lib']).toBeUndefined();
  });

  it('parses v1 nested lockfiles', () => {
    const map = byName(
      parseNpmLock({
        relPath: 'package-lock.json',
        content: load('npm-v1', 'package-lock.json'),
        companions: {},
      }),
    );
    expect(map.express.direct).toBe(true);
    expect(map.qs.dependencyPath).toEqual(['express', 'qs']);
  });
});

describe('yarn.lock', () => {
  it('parses classic lockfiles using package.json for directs', () => {
    const map = byName(
      parseYarnClassic(load('yarn-classic', 'yarn.lock'), 'yarn.lock', new Set(['express'])),
    );
    expect(map.express.direct).toBe(true);
    expect(map.qs).toMatchObject({ direct: false, dependencyPath: ['express', 'qs'] });
  });

  it('parses berry lockfiles', () => {
    const map = byName(
      yarnParser.parse({
        relPath: 'yarn.lock',
        content: load('yarn-berry', 'yarn.lock'),
        companions: { 'package.json': load('yarn-berry', 'package.json') },
      }),
    );
    expect(map.express.direct).toBe(true);
    expect(map.qs.dependencyPath).toEqual(['express', 'qs']);
  });
});

describe('pnpm-lock.yaml', () => {
  it('splits v5/v6/v9 keys', () => {
    expect(splitPnpmKey('express@4.17.1')).toEqual({ name: 'express', version: '4.17.1' });
    expect(splitPnpmKey('/express@4.17.1')).toEqual({ name: 'express', version: '4.17.1' });
    expect(splitPnpmKey('/express/4.17.1')).toEqual({ name: 'express', version: '4.17.1' });
    expect(splitPnpmKey('/@scope/name@1.0.0')).toEqual({ name: '@scope/name', version: '1.0.0' });
    expect(splitPnpmKey('express@4.17.1(@types/node@18.0.0)')).toEqual({
      name: 'express',
      version: '4.17.1',
    });
  });

  it('parses v9 lockfiles with importer directs', () => {
    const map = byName(parsePnpmLock(load('pnpm', 'pnpm-lock.yaml'), 'pnpm-lock.yaml'));
    expect(map.express.direct).toBe(true);
    expect(map.qs).toMatchObject({ direct: false, dependencyPath: ['express', 'qs'] });
  });
});

describe('Cargo.lock', () => {
  it('treats unsourced workspace members as roots, not components', () => {
    const components = parseCargoLock(load('cargo', 'Cargo.lock'), 'Cargo.lock');
    expect(components.map((c) => c.name)).toEqual(['serde', 'serde_derive']);
    const map = byName(components);
    expect(map.serde.direct).toBe(true);
    expect(map.serde_derive).toMatchObject({
      direct: false,
      dependencyPath: ['serde', 'serde_derive'],
      ecosystem: 'crates.io',
      purl: 'pkg:cargo/serde_derive@1.0.188',
    });
  });
});

describe('go.mod / go.sum', () => {
  it('marks go.mod requires as direct and go.sum-only modules as transitive without a path', () => {
    const map = byName(
      parseGoModules(load('go', 'go.mod'), load('go', 'go.sum'), 'go.sum'),
    );
    expect(map['github.com/pkg/errors']).toMatchObject({
      version: 'v0.9.1',
      direct: true,
      dependencyPath: ['github.com/pkg/errors'],
      ecosystem: 'Go',
    });
    expect(map['github.com/kr/pretty']).toMatchObject({
      version: 'v0.3.1',
      direct: false,
      dependencyPath: [],
    });
    // Present only in go.sum — no graph, empty path.
    expect(map['github.com/rogpeppe/go-internal']).toMatchObject({
      version: 'v1.9.0',
      direct: false,
      dependencyPath: [],
    });
  });
});

describe('poetry.lock', () => {
  it('uses pyproject.toml for directs and the lock graph for paths', () => {
    const map = byName(
      parsePoetryLock(load('poetry', 'poetry.lock'), 'poetry.lock', load('poetry', 'pyproject.toml')),
    );
    expect(map.requests.direct).toBe(true);
    expect(map.certifi).toMatchObject({
      direct: false,
      dependencyPath: ['requests', 'certifi'],
      ecosystem: 'PyPI',
    });
  });
});

describe('requirements.txt', () => {
  it('keeps only pinned lines and treats them as direct', () => {
    const components = parseRequirementsTxt(load('pip', 'requirements.txt'), 'requirements.txt');
    expect(components.map((c) => c.name).sort()).toEqual(['certifi', 'requests']);
    expect(components.every((c) => c.direct && c.dependencyPath.length === 1)).toBe(true);
  });
});

describe('Gemfile.lock', () => {
  it('uses DEPENDENCIES as directs and specs as the graph', () => {
    const map = byName(parseGemfileLock(load('gem', 'Gemfile.lock'), 'Gemfile.lock'));
    expect(map.sinatra.direct).toBe(true);
    expect(map.rack).toMatchObject({
      version: '2.2.8',
      direct: false,
      dependencyPath: ['sinatra', 'rack'],
      ecosystem: 'RubyGems',
    });
  });
});

describe('Maven / Gradle', () => {
  it('resolves pom properties and managed versions, skipping ranges', () => {
    const map = byName(parsePomXml(load('maven', 'pom.xml'), 'pom.xml'));
    expect(map['org.apache.commons:commons-lang3']).toMatchObject({
      version: '3.12.0',
      direct: true,
    });
    expect(map['com.google.guava:guava'].version).toBe('32.1.2-jre');
    expect(map['org.example:ranged']).toBeUndefined();
  });

  it('uses the child POM version for ${project.version}, not the parent', () => {
    const map = byName(parsePomXml(load('maven-parent', 'pom.xml'), 'pom.xml'));
    expect(map['com.acme:child-app'].version).toBe('1.2.3');
    expect(map['com.acme:parent-bom-note'].version).toBe('9.9.9');
  });

  it('parses gradle.lockfile as a flat list without a graph', () => {
    const map = byName(parseGradleLockfile(load('gradle', 'gradle.lockfile'), 'gradle.lockfile'));
    expect(map['org.apache.commons:commons-lang3']).toMatchObject({
      version: '3.12.0',
      direct: false,
      dependencyPath: [],
    });
  });
});

describe('composer.lock', () => {
  it('strips the v prefix and builds a path from require', () => {
    const map = byName(
      parseComposerLock(
        load('composer', 'composer.lock'),
        'composer.lock',
        load('composer', 'composer.json'),
      ),
    );
    expect(map['monolog/monolog']).toMatchObject({
      version: '3.5.0',
      direct: true,
      licenses: ['MIT'],
    });
    expect(map['psr/log']).toMatchObject({
      direct: false,
      dependencyPath: ['monolog/monolog', 'psr/log'],
    });
  });
});

describe('NuGet', () => {
  it('parses packages.lock.json Direct vs Transitive', () => {
    const map = byName(parsePackagesLock(load('nuget-lock', 'packages.lock.json'), 'packages.lock.json'));
    expect(map['Newtonsoft.Json'].direct).toBe(true);
    expect(map['Microsoft.CSharp']).toMatchObject({
      direct: false,
      dependencyPath: ['Newtonsoft.Json', 'Microsoft.CSharp'],
    });
  });

  it('parses pinned PackageReference items from csproj and skips ranges', () => {
    const map = byName(parseCsproj(load('csproj', 'app.csproj'), 'app.csproj'));
    expect(map['Newtonsoft.Json'].version).toBe('13.0.3');
    expect(map.Serilog.version).toBe('3.1.1');
    expect(map['Loose.Range']).toBeUndefined();
  });
});

describe('resolveLockfiles', () => {
  it('walks a repo and merges ecosystems without hitting the network', async () => {
    const components = await resolveLockfiles(join(FIX, 'mixed'));
    const map = byName(components);
    expect(map.express).toMatchObject({ ecosystem: 'npm', version: '4.17.1' });
    expect(map.libc).toMatchObject({ ecosystem: 'crates.io', version: '0.2.150', direct: true });
  });

  it('prefers poetry.lock over requirements.txt in the same directory', async () => {
    const components = await resolveLockfiles(join(FIX, 'poetry'));
    expect(components.every((c) => c.manifestPath.endsWith('poetry.lock'))).toBe(true);
  });

  it('keeps the same package from two manifests (monorepo) as separate components', async () => {
    const components = await resolveLockfiles(join(FIX, 'monorepo'));
    const lodashes = components.filter((c) => c.name === 'lodash');
    expect(lodashes).toHaveLength(2);
    expect(lodashes.map((c) => c.manifestPath).sort()).toEqual([
      'app-a/package-lock.json',
      'app-b/package-lock.json',
    ]);
  });

  it('throws when every selected lockfile fails to parse', async () => {
    await expect(resolveLockfiles(join(FIX, 'corrupt'))).rejects.toThrow(LockfileResolutionError);
  });

  it('reads only the lockfile and declared companions, not every sibling', () => {
    const dirFiles = [
      { absPath: '/r/yarn.lock', relPath: 'yarn.lock', fileName: 'yarn.lock' },
      { absPath: '/r/package.json', relPath: 'package.json', fileName: 'package.json' },
      { absPath: '/r/README.md', relPath: 'README.md', fileName: 'README.md' },
      { absPath: '/r/huge.bin', relPath: 'huge.bin', fileName: 'huge.bin' },
    ];
    expect(filesToRead(yarnParser, 'yarn.lock', dirFiles).map((f) => f.fileName)).toEqual([
      'yarn.lock',
      'package.json',
    ]);
    expect(
      filesToRead(npmParser, 'package-lock.json', [
        { absPath: '/r/package-lock.json', relPath: 'package-lock.json', fileName: 'package-lock.json' },
        ...dirFiles,
      ]).map((f) => f.fileName),
    ).toEqual(['package-lock.json']);
  });
});
