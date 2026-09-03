import { mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { IacAnalyzer, IacAnalysisError } from './analyzer';
import { MisconfigRules } from './misconfig.rules';

const VULN = join(__dirname, '__fixtures__', 'vulnerable');
const CLEAN = join(__dirname, '__fixtures__', 'clean');
const NO_IAC = join(__dirname, '__fixtures__', 'no-iac');
const UNPARSED = join(__dirname, '__fixtures__', 'unparsed');
const analyzer = new IacAnalyzer(new MisconfigRules());

async function repo(files: Record<string, string>): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'ctem-iac-'));
  for (const [rel, content] of Object.entries(files)) {
    const abs = join(dir, rel);
    await mkdir(join(abs, '..'), { recursive: true });
    await writeFile(abs, content);
  }
  return dir;
}

describe('IacAnalyzer', () => {
  it('hits built-in rules on vulnerable fixtures', async () => {
    const { matches, parsed } = await analyzer.analyze(VULN);
    expect(parsed).toBeGreaterThan(0);
    const ids = matches.map((m) => m.rule.id);
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
    const buckets = matches.filter((m) => m.rule.id === 'ctem.iac.s3-public' && m.path === 's3.tf');
    expect(buckets.map((m) => m.address).sort()).toEqual(['aws_s3_bucket.assets', 'aws_s3_bucket.logs']);
  });

  it('produces zero matches on clean IaC after a successful parse', async () => {
    const { matches, parsed } = await analyzer.analyze(CLEAN);
    expect(parsed).toBeGreaterThan(0);
    expect(matches).toEqual([]);
  });

  it('treats a repo with no IaC files as empty success', async () => {
    const { matches, detected, parsed } = await analyzer.analyze(NO_IAC);
    expect(detected).toBe(0);
    expect(parsed).toBe(0);
    expect(matches).toEqual([]);
  });

  it('fails when every detected IaC file is unparsed', async () => {
    await expect(analyzer.analyze(UNPARSED)).rejects.toThrow(/parsed none/);
  });

  it('fails when the workDir is empty (no checkout)', async () => {
    const workDir = await mkdtemp(join(tmpdir(), 'ctem-iac-empty-'));
    await expect(analyzer.analyze(workDir)).rejects.toThrow(/workDir is empty/);
  });

  it('fails the job when the deadline expires before parse completes', async () => {
    await expect(analyzer.analyze(CLEAN, () => false)).rejects.toThrow(/deadline/);
  });

  it('fails the job when any detected IaC file is unparsed, even if another *.tf parsed', async () => {
    const workDir = await repo({
      'ok.tf': 'resource "aws_s3_bucket" "ok" {\n  bucket = "ok"\n  acl = "private"\n  server_side_encryption_configuration {\n    rule {\n      apply_server_side_encryption_by_default {\n        sse_algorithm = "aws:kms"\n      }\n    }\n  }\n}\n',
      'bad.tf': 'resource "aws_s3_bucket" "x" {\n  acl =\n',
    });
    await expect(analyzer.analyze(workDir)).rejects.toThrow(/failed to parse 'bad\.tf'/);
  });
});

describe('IacAnalyzer errors', () => {
  it('wraps missing workDir as IacAnalysisError', async () => {
    await expect(analyzer.analyze('/no/such/ctem-iac-workDir')).rejects.toThrow(IacAnalysisError);
  });
});
