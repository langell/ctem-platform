import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it, vi } from 'vitest';
import { CheckoutError, GitRepoCheckout, type ScanContext } from '@ctem/scanner-sdk';
import { SastAnalyzer } from './analyzer';
import { emptySastGraph, SastAnalysisError } from './graph';
import { RuleEngine } from './rule-engine';
import { SastScanner } from './sast.scanner';

const VULN = join(__dirname, '__fixtures__', 'vulnerable');
const CLEAN = join(__dirname, '__fixtures__', 'clean');

function ctx(overrides: Partial<ScanContext['job']> = {}, workDir = VULN): ScanContext {
  return {
    job: {
      jobId: randomUUID(),
      scanId: randomUUID(),
      orgId: randomUUID(),
      scannerType: 'sast',
      assetId: randomUUID(),
      target: { kind: 'repository', htmlUrl: 'https://github.com/acme/app', defaultBranch: 'main' },
      credentialRef: null,
      options: {},
      attempt: 1,
      deadlineAt: new Date(Date.now() + 60_000),
      traceId: 'test',
      ...overrides,
    },
    workDir,
    checkDeadline: () => true,
    log: () => undefined,
  };
}

function scanner(
  checkout: { checkout: (c: ScanContext) => Promise<void> } = { checkout: async () => undefined },
  analyzer?: SastAnalyzer,
): SastScanner {
  const rules = new RuleEngine();
  return new SastScanner(
    rules,
    checkout as unknown as GitRepoCheckout,
    analyzer ?? new SastAnalyzer(rules),
  );
}

describe('SastScanner.execute', () => {
  it('supports only repository targets', () => {
    const s = scanner();
    expect(s.supports({ target: { kind: 'repository' } } as never)).toBe(true);
    expect(s.supports({ target: { kind: 'container_image' } } as never)).toBe(false);
  });

  it('throws on a missing or refused clone URL instead of succeeding with findings:[]', async () => {
    const s = new SastScanner(new RuleEngine(), new GitRepoCheckout());
    await expect(
      s.execute(ctx({ target: { kind: 'repository', htmlUrl: 'https://github.com/acme/app' } })),
    ).rejects.toThrow(CheckoutError);
    await expect(
      s.execute(ctx({ target: { cloneUrl: 'https://evil.example/acme/app.git' } })),
    ).rejects.toThrow(/only github.com and gitlab.com are allowlisted/);
    await expect(s.execute(ctx({ target: { cloneUrl: 'git@github.com:acme/app.git' } }))).rejects.toThrow(/git@/);
    await expect(
      s.execute(
        ctx({
          target: {
            kind: 'repository',
            externalKey: 'github:acme/app',
            cloneUrl: 'https://github.com/evil/other.git',
          },
        }),
      ),
    ).rejects.toThrow(/does not match asset identity/);
    await expect(
      s.execute(
        ctx({
          target: { kind: 'repository', externalKey: 'github:acme/app', private: true },
          credentialRef: null,
        }),
      ),
    ).rejects.toThrow(/Private repository requires a usable credentialRef/);
  });

  it('fails when workDir is empty without a successful checkout', async () => {
    const workDir = await mkdtemp(join(tmpdir(), 'ctem-sast-empty-'));
    const checkout = { checkout: vi.fn(async () => undefined) };
    await expect(scanner(checkout).execute(ctx({}, workDir))).rejects.toThrow(/workDir is empty/);
    expect(checkout.checkout).toHaveBeenCalledOnce();
  });

  it('emits sast RawFindings from built-in rules after checkout', async () => {
    const checkout = { checkout: vi.fn(async () => undefined) };
    const outcome = await scanner(checkout).execute(ctx({ target: { kind: 'repository', externalKey: 'github:acme/app' } }));
    expect(checkout.checkout).toHaveBeenCalledOnce();
    expect(outcome.findings.length).toBeGreaterThan(0);
    expect(outcome.findings.every((f) => f.scannerType === 'sast')).toBe(true);
    expect(outcome.findings.every((f) => /^ctem\.[^:]+:.+:\d+$/.test(f.externalId))).toBe(true);
    expect(outcome.findings.some((f) => f.identifiers.some((i) => i.system === 'CWE' && i.value === 'CWE-89'))).toBe(
      true,
    );
    expect(outcome.findings.some((f) => f.identifiers.some((i) => i.system === 'CWE' && i.value === 'CWE-78'))).toBe(
      true,
    );
    expect(outcome.findings.some((f) => f.identifiers.some((i) => i.system === 'CWE' && i.value === 'CWE-798'))).toBe(
      true,
    );
    const injection = outcome.findings.find((f) => f.externalId.startsWith('ctem.sql-injection:'));
    expect(injection?.evidence.reachability).toBe('reachable');
    expect(outcome.stats?.files).toBeGreaterThan(0);
  });

  it('returns findings:[] only after a successful graph on clean source, not a skipped analyzer', async () => {
    const checkout = { checkout: vi.fn(async () => undefined) };
    const outcome = await scanner(checkout).execute(
      ctx({ target: { kind: 'repository', externalKey: 'github:acme/app' } }, CLEAN),
    );
    expect(outcome.findings).toEqual([]);
    expect(outcome.stats?.files).toBeGreaterThan(0);
    const graph = (outcome.rawOutput as { graph: { files: string[] } }).graph;
    expect(graph.files.length).toBeGreaterThan(0);
  });

  it('fails the job when analysis crashes instead of succeeding with findings:[]', async () => {
    const checkout = { checkout: vi.fn(async () => undefined) };
    const analyzer = {
      analyze: vi.fn(async () => {
        throw new Error('parser panicked');
      }),
    };
    const s = new SastScanner(
      new RuleEngine(),
      checkout as unknown as GitRepoCheckout,
      analyzer as unknown as SastAnalyzer,
    );
    await expect(s.execute(ctx())).rejects.toThrow(SastAnalysisError);
  });

  it('fails the job when analysis times out before a graph is produced', async () => {
    const checkout = { checkout: vi.fn(async () => undefined) };
    await expect(scanner(checkout).execute({ ...ctx(), checkDeadline: () => false })).rejects.toThrow(/deadline/);
  });

  it('fails the job when analysis returns no graph instead of empty success', async () => {
    const checkout = { checkout: vi.fn(async () => undefined) };
    const analyzer = { analyze: vi.fn(async () => ({ graph: null, matches: [] })) };
    const s = new SastScanner(
      new RuleEngine(),
      checkout as unknown as GitRepoCheckout,
      analyzer as unknown as SastAnalyzer,
    );
    await expect(s.execute(ctx())).rejects.toThrow(/did not produce a graph/);
  });

  it('ignores a tenant-supplied script or pattern pack and never executes it', async () => {
    const checkout = { checkout: vi.fn(async () => undefined) };
    const analyzerSources = ['analyzer.ts', 'rule-engine.ts', 'taint.ts', 'sast.scanner.ts']
      .map((name) => readFileSync(join(__dirname, name), 'utf8'))
      .join('\n');
    expect(analyzerSources).not.toMatch(
      /from ['"]node:child_process['"]|from ['"]child_process['"]|require\(['"]child_process/,
    );

    const outcome = await scanner(checkout).execute(
      ctx({
        target: { kind: 'repository', externalKey: 'github:acme/app' },
        options: {
          script: 'semgrep --config=/tmp/tenant.yml',
          rulesYaml: 'rules:\n  - id: tenant.custom\n    pattern: anything\n',
          patternPack: 'https://evil.example/pack.yaml',
          customRules: [{ id: 'tenant.custom', pattern: 'eval($X)' }],
        },
      }),
    );
    expect(outcome.findings.some((f) => f.externalId.includes('tenant.custom'))).toBe(false);
    expect(outcome.findings.some((f) => f.externalId.startsWith('ctem.sql-injection:'))).toBe(true);
    expect((outcome.rawOutput as { ignoredTenantOptions: string[] }).ignoredTenantOptions).toEqual(
      expect.arrayContaining(['script', 'rulesYaml', 'patternPack', 'customRules']),
    );
  });

  it('does not copy SCA package-reachability or claim a lockfile is reachable', async () => {
    const workDir = await mkdtemp(join(tmpdir(), 'ctem-sast-lock-'));
    await writeFile(
      join(workDir, 'package-lock.json'),
      JSON.stringify({ lockfileVersion: 3, packages: { '': { dependencies: { express: '4.17.1' } } } }),
    );
    await writeFile(join(workDir, 'ok.js'), "db.query('SELECT 1');\n");
    const checkout = { checkout: vi.fn(async () => undefined) };
    const outcome = await scanner(checkout).execute(
      ctx({ target: { kind: 'repository', externalKey: 'github:acme/app' } }, workDir),
    );
    expect(outcome.findings).toEqual([]);
    expect(outcome.findings.every((f) => f.evidence.reachability !== 'reachable')).toBe(true);
    const graph = emptySastGraph();
    expect(graph.taintFlows).toEqual([]);
  });
});
