import { chmod, mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { SastAnalyzer } from './analyzer';
import { isSastGraph, SastAnalysisError, verdictForMatch } from './graph';
import { RuleEngine } from './rule-engine';

const VULN = join(__dirname, '__fixtures__', 'vulnerable');
const CLEAN = join(__dirname, '__fixtures__', 'clean');
const analyzer = new SastAnalyzer(new RuleEngine());

async function emptyDir(): Promise<string> {
  return mkdtemp(join(tmpdir(), 'ctem-sast-empty-'));
}

async function repo(files: Record<string, string>): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'ctem-sast-'));
  for (const [rel, content] of Object.entries(files)) {
    const abs = join(dir, rel);
    await mkdir(join(abs, '..'), { recursive: true });
    await writeFile(abs, content);
  }
  return dir;
}

describe('SastAnalyzer', () => {
  it('builds a graph and hits built-in rules on vulnerable fixtures', async () => {
    const { graph, matches } = await analyzer.analyze(VULN);
    expect(isSastGraph(graph)).toBe(true);
    expect(graph.files.size).toBeGreaterThan(0);
    expect(graph.imports.size).toBeGreaterThan(0);
    expect(graph.taintFlows.length).toBeGreaterThan(0);
    expect(matches.map((m) => m.rule.id)).toEqual(
      expect.arrayContaining(['ctem.sql-injection', 'ctem.command-injection', 'ctem.hardcoded-secret']),
    );
    const sql = matches.find((m) => m.rule.id === 'ctem.sql-injection' && m.path.endsWith('sql.js'));
    expect(sql).toBeTruthy();
    expect(verdictForMatch({ ruleId: sql!.rule.id, path: sql!.path, startLine: sql!.startLine }, graph)).toBe(
      'reachable',
    );
  });

  it('produces a graph on clean fixtures and does not treat that as skipped-analyzer success', async () => {
    const { graph, matches } = await analyzer.analyze(CLEAN);
    expect(isSastGraph(graph)).toBe(true);
    expect(graph.files.size).toBeGreaterThan(0);
    expect(matches).toEqual([]);
  });

  it('does not treat lockfile or manifest presence as reachable', async () => {
    const workDir = await repo({
      'package-lock.json': JSON.stringify({ lockfileVersion: 3, packages: { '': { dependencies: { express: '4.17.1' } } } }),
      'src/ok.js': "db.query('SELECT 1');\n",
    });
    const { graph, matches } = await analyzer.analyze(workDir);
    expect(isSastGraph(graph)).toBe(true);
    expect(matches).toEqual([]);
    expect(graph.taintFlows).toEqual([]);
    expect(
      verdictForMatch({ ruleId: 'ctem.sql-injection', path: 'src/ok.js', startLine: 1 }, graph),
    ).toBe('not_reachable');
  });

  it('fails when the workDir is empty (no checkout)', async () => {
    const workDir = await emptyDir();
    await expect(analyzer.analyze(workDir)).rejects.toThrow(/workDir is empty/);
  });

  it('fails when the workDir cannot be read', async () => {
    await expect(analyzer.analyze('/no/such/ctem-sast-workDir')).rejects.toThrow(SastAnalysisError);
  });

  it('fails the job when the deadline expires before a graph is produced', async () => {
    await expect(analyzer.analyze(CLEAN, [], () => false)).rejects.toThrow(/deadline/);
  });

  it('fails when every source file is unreadable rather than returning an empty graph', async () => {
    const workDir = await repo({ 'app.js': "db.query('SELECT * FROM t WHERE id = ' + req.query.id);\n" });
    await chmod(join(workDir, 'app.js'), 0);
    try {
      await expect(analyzer.analyze(workDir)).rejects.toThrow(SastAnalysisError);
    } finally {
      await chmod(join(workDir, 'app.js'), 0o644);
    }
  });
});
