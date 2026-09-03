import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { RuleEngine } from './rule-engine';

const VULN = join(__dirname, '__fixtures__', 'vulnerable');
const CLEAN = join(__dirname, '__fixtures__', 'clean');
const engine = new RuleEngine();

describe('RuleEngine built-in seed rules', () => {
  it('matches SQL injection, command injection, and hardcoded secret fixtures', async () => {
    const matches = await engine.run(VULN, []);
    const ids = matches.map((m) => m.rule.id).sort();
    expect(ids).toEqual(
      expect.arrayContaining(['ctem.sql-injection', 'ctem.command-injection', 'ctem.hardcoded-secret']),
    );
    expect(matches.find((m) => m.rule.id === 'ctem.sql-injection' && m.path.endsWith('sql.js'))).toMatchObject({
      startLine: expect.any(Number),
    });
    expect(matches.find((m) => m.rule.id === 'ctem.command-injection' && m.path.endsWith('cmd.py'))).toBeTruthy();
    expect(matches.find((m) => m.rule.id === 'ctem.sql-injection' && m.path.endsWith('inject.py'))).toBeTruthy();
    expect(matches.find((m) => m.rule.id === 'ctem.hardcoded-secret' && m.path.endsWith('secret.ts'))).toBeTruthy();
    expect(matches.every((m) => m.rule.cwe.length > 0)).toBe(true);
  });

  it('does not match parameterized or env-loaded clean fixtures', async () => {
    const matches = await engine.run(CLEAN, []);
    expect(matches).toEqual([]);
  });

  it('does not execute or consult a tenant-supplied pattern pack', async () => {
    const listed = engine.list(['javascript']);
    expect(listed.every((r) => r.id.startsWith('ctem.'))).toBe(true);
    expect(listed.some((r) => r.id === 'tenant.custom')).toBe(false);
  });
});
