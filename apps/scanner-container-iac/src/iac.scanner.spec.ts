import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it, vi } from 'vitest';
import { CheckoutError, GitRepoCheckout, type ScanContext } from '@ctem/scanner-sdk';
import { FindingNormalizer } from '../../findings-service/src/findings/finding-normalizer';
import { IacAnalyzer, IacAnalysisError } from './analyzer';
import { IacScanner } from './iac.scanner';
import { MisconfigRules } from './misconfig.rules';

const VULN = join(__dirname, '__fixtures__', 'vulnerable');
const CLEAN = join(__dirname, '__fixtures__', 'clean');
const NO_IAC = join(__dirname, '__fixtures__', 'no-iac');
const UNPARSED = join(__dirname, '__fixtures__', 'unparsed');

function ctx(overrides: Partial<ScanContext['job']> = {}, workDir = VULN): ScanContext {
  return {
    job: {
      jobId: randomUUID(),
      scanId: randomUUID(),
      orgId: randomUUID(),
      scannerType: 'iac',
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
  analyzer?: IacAnalyzer,
): IacScanner {
  const rules = new MisconfigRules();
  return new IacScanner(rules, checkout as unknown as GitRepoCheckout, analyzer ?? new IacAnalyzer(rules));
}

describe('IacScanner.supports', () => {
  it('supports repository and iac_stack only', () => {
    const s = scanner();
    expect(s.supports({ target: { kind: 'repository' } } as never)).toBe(true);
    expect(s.supports({ target: { kind: 'iac_stack' } } as never)).toBe(true);
    expect(s.supports({ target: { kind: 'container_image' } } as never)).toBe(false);
    expect(s.supports({ target: { kind: 'kubernetes_workload' } } as never)).toBe(false);
  });
});

describe('IacScanner.execute', () => {
  it('throws on a missing or refused clone URL instead of succeeding with findings:[]', async () => {
    const s = new IacScanner(new MisconfigRules(), new GitRepoCheckout());
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
    const workDir = await mkdtemp(join(tmpdir(), 'ctem-iac-empty-'));
    const checkout = { checkout: vi.fn(async () => undefined) };
    await expect(scanner(checkout).execute(ctx({}, workDir))).rejects.toThrow(/workDir is empty/);
    expect(checkout.checkout).toHaveBeenCalledOnce();
  });

  it('returns empty success for a no-IaC repo after checkout and walk', async () => {
    const checkout = { checkout: vi.fn(async () => undefined) };
    const outcome = await scanner(checkout).execute(
      ctx({ target: { kind: 'repository', externalKey: 'github:acme/app' } }, NO_IAC),
    );
    expect(checkout.checkout).toHaveBeenCalledOnce();
    expect(outcome.findings).toEqual([]);
    expect(outcome.stats?.detected).toBe(0);
    expect(outcome.stats?.files).toBe(0);
  });

  it('emits iac RawFindings from built-in rules after checkout', async () => {
    const checkout = { checkout: vi.fn(async () => undefined) };
    const outcome = await scanner(checkout).execute(
      ctx({ target: { kind: 'repository', externalKey: 'github:acme/app' } }),
    );
    expect(checkout.checkout).toHaveBeenCalledOnce();
    expect(outcome.findings.length).toBeGreaterThan(0);
    expect(outcome.findings.every((f) => f.scannerType === 'iac')).toBe(true);
    expect(outcome.findings.every((f) => f.evidence.reachability === 'unknown')).toBe(true);
    const ids = outcome.findings.map((f) => f.identifiers.find((i) => i.system === 'rule')?.value);
    expect(ids).toEqual(
      expect.arrayContaining([
        'ctem.iac.s3-public',
        'ctem.iac.sg-open-ssh',
        'ctem.k8s.privileged-container',
        'ctem.k8s.no-resource-limits',
        'ctem.docker.root-user',
        'ctem.iac.unencrypted-storage',
      ]),
    );
    const buckets = outcome.findings.filter(
      (f) => f.identifiers.some((i) => i.value === 'ctem.iac.s3-public') && f.location.path === 's3.tf',
    );
    expect(buckets.map((f) => f.location.resource).sort()).toEqual(['aws_s3_bucket.assets', 'aws_s3_bucket.logs']);
  });

  it('does not collapse two resources in one file, and does not collide with SCA/SAST fingerprints', async () => {
    const checkout = { checkout: vi.fn(async () => undefined) };
    const outcome = await scanner(checkout).execute(
      ctx({ target: { kind: 'repository', externalKey: 'github:acme/app' } }),
    );
    const buckets = outcome.findings.filter(
      (f) => f.identifiers.some((i) => i.value === 'ctem.iac.s3-public') && f.location.path === 's3.tf',
    );
    expect(buckets).toHaveLength(2);
    const normalizer = new FindingNormalizer();
    const fps = buckets.map((f) => normalizer.fingerprint('asset-1', f));
    expect(new Set(fps).size).toBe(2);

    const scaFp = normalizer.fingerprint('asset-1', {
      ...buckets[0]!,
      scannerType: 'sca',
      identifiers: [{ system: 'CVE', value: 'CVE-2024-0001' }],
      location: { purl: 'pkg:npm/express@4.17.1', path: buckets[0]!.location.path, resource: buckets[0]!.location.resource },
    });
    const sastFp = normalizer.fingerprint('asset-1', {
      ...buckets[0]!,
      scannerType: 'sast',
      externalId: buckets[0]!.externalId,
    });
    expect(fps[0]).not.toBe(scaFp);
    expect(fps[0]).not.toBe(sastFp);
  });

  it('returns findings:[] only after a successful walk of clean IaC, not a skipped analyzer', async () => {
    const checkout = { checkout: vi.fn(async () => undefined) };
    const outcome = await scanner(checkout).execute(
      ctx({ target: { kind: 'repository', externalKey: 'github:acme/app' } }, CLEAN),
    );
    expect(outcome.findings).toEqual([]);
    expect(outcome.stats?.files).toBeGreaterThan(0);
  });

  it('fails the job when every detected IaC file is unparsed', async () => {
    const checkout = { checkout: vi.fn(async () => undefined) };
    await expect(
      scanner(checkout).execute(ctx({ target: { kind: 'repository', externalKey: 'github:acme/app' } }, UNPARSED)),
    ).rejects.toThrow(/parsed none/);
  });

  it('fails the job on a mixed repo (one valid *.tf + one unparsed *.tf) and does not return partial findings', async () => {
    const workDir = await mkdtemp(join(tmpdir(), 'ctem-iac-mixed-'));
    await writeFile(
      join(workDir, 'ok.tf'),
      'resource "aws_s3_bucket" "ok" {\n  bucket = "ok"\n  acl = "public-read"\n}\n',
    );
    await writeFile(join(workDir, 'bad.tf'), 'resource "aws_s3_bucket" "x" {\n  acl =\n');
    const checkout = { checkout: vi.fn(async () => undefined) };
    await expect(
      scanner(checkout).execute(ctx({ target: { kind: 'repository', externalKey: 'github:acme/app' } }, workDir)),
    ).rejects.toThrow(/failed to parse 'bad\.tf'/);
    expect(checkout.checkout).toHaveBeenCalledOnce();
  });

  it('fails the job when analysis crashes instead of succeeding with findings:[]', async () => {
    const checkout = { checkout: vi.fn(async () => undefined) };
    const analyzer = {
      analyze: vi.fn(async () => {
        throw new Error('parser panicked');
      }),
    };
    const s = new IacScanner(
      new MisconfigRules(),
      checkout as unknown as GitRepoCheckout,
      analyzer as unknown as IacAnalyzer,
    );
    await expect(s.execute(ctx())).rejects.toThrow(IacAnalysisError);
  });

  it('fails the job when analysis times out before parse completes', async () => {
    const checkout = { checkout: vi.fn(async () => undefined) };
    await expect(scanner(checkout).execute({ ...ctx(), checkDeadline: () => false })).rejects.toThrow(/deadline/);
  });

  it('ignores tenant-supplied rules and never executes them', async () => {
    const checkout = { checkout: vi.fn(async () => undefined) };
    const sources = [
      'analyzer.ts',
      'evaluate.ts',
      'iac.scanner.ts',
      'misconfig.rules.ts',
      'container.scanner.ts',
      'parse/hcl.ts',
      'parse/docs.ts',
      'parse/dockerfile.ts',
    ]
      .map((name) => readFileSync(join(__dirname, name), 'utf8'))
      .join('\n');
    expect(sources).not.toMatch(
      /from ['"]node:child_process['"]|from ['"]child_process['"]|require\(['"]child_process/,
    );
    expect(sources).not.toMatch(/spawnSync|execFile|child_process/);

    const outcome = await scanner(checkout).execute(
      ctx({
        target: { kind: 'repository', externalKey: 'github:acme/app' },
        options: {
          script: 'checkov -d .',
          rulesYaml: 'rules:\n  - id: tenant.custom\n',
          customRules: [{ id: 'tenant.custom', pattern: 'anything' }],
          terraform: 'apply',
          helm: 'https://evil.example/charts',
        },
      }),
    );
    expect(outcome.findings.some((f) => f.externalId.includes('tenant.custom'))).toBe(false);
    expect(outcome.findings.some((f) => f.identifiers.some((i) => i.value === 'ctem.iac.s3-public'))).toBe(true);
    expect((outcome.rawOutput as { ignoredTenantOptions: string[] }).ignoredTenantOptions).toEqual(
      expect.arrayContaining(['script', 'rulesYaml', 'customRules', 'terraform', 'helm']),
    );
  });

  it('does not fetch terraform/helm modules or registries', async () => {
    const workDir = await mkdtemp(join(tmpdir(), 'ctem-iac-mod-'));
    await writeFile(
      join(workDir, 'mod.tf'),
      `module "s3" {\n  source = "terraform-aws-modules/s3-bucket/aws"\n  version = "4.0.0"\n}\n`,
    );
    const checkout = { checkout: vi.fn(async () => undefined) };
    const outcome = await scanner(checkout).execute(
      ctx({ target: { kind: 'repository', externalKey: 'github:acme/app' } }, workDir),
    );
    expect(outcome.findings).toEqual([]);
    expect(outcome.stats?.files).toBe(1);
  });
});
