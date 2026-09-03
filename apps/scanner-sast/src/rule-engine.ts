import { readFile } from 'node:fs/promises';
import { Injectable } from '@nestjs/common';
import type { Severity } from '@ctem/contracts';
import { analyzeFile, type FileGraph } from './taint';
import { findCalls, firstArg, isInterpolatedArg, languageOf, lineSnippet, stripCommentsPreserve, type SastLanguage } from './source';
import { listRepoFiles } from './walk';

export interface Rule {
  id: string;
  name: string;
  severity: Severity;
  languages: string[];
  cwe: string[];
  /** Built-in detector key — not a tenant-supplied Semgrep/YAML pattern. */
  pattern: string;
  message: string;
}

export interface RuleMatch {
  rule: Rule;
  path: string;
  startLine: number;
  endLine: number;
  snippet: string;
  /** Populated by taint analysis: where untrusted input entered. */
  dataflow?: Array<{ path: string; line: number; label: 'source' | 'propagator' | 'sink' }>;
}

/**
 * In-process built-in rule engine. Seed rules are compiled detectors in this
 * process — no tenant-supplied script, YAML pack, or shell-out to Semgrep,
 * Bandit, CodeQL, eslint, or a language toolchain.
 */
@Injectable()
export class RuleEngine {
  private readonly rules: Rule[] = [
    {
      id: 'ctem.sql-injection',
      name: 'SQL query built from untrusted input',
      severity: 'high',
      languages: ['javascript', 'typescript', 'python'],
      cwe: ['CWE-89'],
      pattern: 'query($X + $Y)',
      message: 'Use parameterized queries instead of string concatenation.',
    },
    {
      id: 'ctem.command-injection',
      name: 'Shell command built from untrusted input',
      severity: 'critical',
      languages: ['javascript', 'typescript', 'python'],
      cwe: ['CWE-78'],
      pattern: 'exec($CMD)',
      message: 'Pass arguments as an array rather than interpolating into a shell string.',
    },
    {
      id: 'ctem.hardcoded-secret',
      name: 'Hard-coded credential',
      severity: 'high',
      languages: ['*'],
      cwe: ['CWE-798'],
      pattern: 'password = "..."',
      message: 'Load credentials from the secret store, not from source.',
    },
  ];

  list(languages?: string[]): Rule[] {
    if (!languages?.length) return this.rules;
    return this.rules.filter(
      (r) => r.languages.includes('*') || r.languages.some((l) => languages.includes(l)),
    );
  }

  /**
   * Match built-in rules over `rootDir`. Callers that need fail-closed graph
   * semantics must go through `SastAnalyzer` — this method only scores files.
   */
  async run(rootDir: string, languages: string[]): Promise<RuleMatch[]> {
    const files = await listRepoFiles(rootDir);
    const matches: RuleMatch[] = [];
    for (const file of files) {
      const language = languageOf(file.fileName);
      if (!language) continue;
      const content = await readFile(file.absPath, 'utf8');
      const analysis = analyzeFile(file.relPath, content, language);
      matches.push(...this.matchSource(content, file.relPath, language, languages, analysis));
    }
    return matches;
  }

  matchSource(
    content: string,
    relPath: string,
    language: SastLanguage,
    languages: string[],
    analysis: FileGraph,
  ): RuleMatch[] {
    const applicable = this.list(languages).filter((rule) => ruleApplies(rule, language));
    const text = stripCommentsPreserve(content, language);
    const matches: RuleMatch[] = [];
    for (const rule of applicable) {
      if (rule.id === 'ctem.hardcoded-secret') {
        matches.push(...matchHardcodedSecrets(rule, content, relPath, text));
        continue;
      }
      matches.push(...matchInjection(rule, content, relPath, language, text, analysis));
    }
    return matches;
  }
}

function ruleApplies(rule: Rule, language: SastLanguage): boolean {
  return rule.languages.includes('*') || rule.languages.includes(language);
}

function matchInjection(
  rule: Rule,
  original: string,
  relPath: string,
  language: SastLanguage,
  text: string,
  analysis: FileGraph,
): RuleMatch[] {
  const matches: RuleMatch[] = [];
  for (const hit of findCalls(text)) {
    if (!isSinkForRule(rule.id, hit.qualified, hit.name)) continue;
    const arg = firstArg(hit.args);
    // Seed patterns are interpolation / a non-literal argument — a lone
    // parameterized string literal is not a finding, even if a later arg is tainted.
    if (!isInterpolatedArg(arg, language)) continue;
    const flow = analysis.taintFlows.find(
      (f) => f.sink.path === relPath && Math.abs(f.sink.line - hit.line) <= 1,
    );
    matches.push({
      rule,
      path: relPath,
      startLine: hit.line,
      endLine: hit.line,
      snippet: lineSnippet(original, hit.line),
      dataflow: flow?.path,
    });
  }
  return matches;
}

function isSinkForRule(ruleId: string, qualified: string, name: string): boolean {
  const q = qualified.toLowerCase();
  const n = name.toLowerCase();
  if (n === 'execfile') return false;
  if (ruleId === 'ctem.sql-injection') {
    return n === 'query' || n === 'execute' || n === 'executemany';
  }
  if (ruleId === 'ctem.command-injection') {
    return (
      n === 'exec' ||
      n === 'execsync' ||
      q === 'os.system' ||
      q === 'os.popen' ||
      q === 'subprocess.call' ||
      q === 'subprocess.run' ||
      q === 'subprocess.popen'
    );
  }
  return false;
}

const SECRET_NAME = /^(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)$/i;
const SECRET_ASSIGN =
  /(?:const|let|var)?\s*([A-Za-z_][\w]*)\s*[:=]\s*(['"])([^'"]{4,})\2/g;

function matchHardcodedSecrets(rule: Rule, original: string, relPath: string, text: string): RuleMatch[] {
  const matches: RuleMatch[] = [];
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i] ?? '';
    SECRET_ASSIGN.lastIndex = 0;
    let found: RegExpExecArray | null;
    while ((found = SECRET_ASSIGN.exec(line)) !== null) {
      const name = found[1] ?? '';
      const value = found[3] ?? '';
      if (!SECRET_NAME.test(name)) continue;
      if (isPlaceholderSecret(value)) continue;
      matches.push({
        rule,
        path: relPath,
        startLine: i + 1,
        endLine: i + 1,
        snippet: lineSnippet(original, i + 1),
      });
    }
  }
  return matches;
}

function isPlaceholderSecret(value: string): boolean {
  return (
    value.includes('${') ||
    value.includes('{{') ||
    /^(changeme|todo|xxx+|your[-_]?secret)$/i.test(value)
  );
}
