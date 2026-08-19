import { Injectable } from '@nestjs/common';
import type { Severity } from '@ctem/contracts';

export interface Rule {
  id: string;
  name: string;
  severity: Severity;
  languages: string[];
  cwe: string[];
  /** Pattern syntax is engine-specific; Semgrep-compatible YAML is the target. */
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
 * Static analysis rule engine.
 *
 * The pragmatic path is to shell out to Semgrep OSS for pattern matching and
 * own the parts that differentiate: rule curation, cross-file taint tracking,
 * and — most importantly — suppressing the noise that makes teams abandon SAST.
 * A tool with a 60% false-positive rate is worse than no tool.
 */
@Injectable()
export class RuleEngine {
  private readonly rules: Rule[] = [
    {
      id: 'ctem.sql-injection',
      name: 'SQL query built from untrusted input',
      severity: 'high',
      languages: ['javascript', 'typescript', 'python', 'java', 'go'],
      cwe: ['CWE-89'],
      pattern: 'query($X + $Y)',
      message: 'Use parameterized queries instead of string concatenation.',
    },
    {
      id: 'ctem.command-injection',
      name: 'Shell command built from untrusted input',
      severity: 'critical',
      languages: ['javascript', 'typescript', 'python', 'ruby'],
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
   * TODO: invoke the underlying analyzer over `rootDir` and map its output onto
   * RuleMatch. Keeping this behind one method means the analyzer can be swapped
   * (or several run in parallel) without touching the scanner.
   */
  async run(_rootDir: string, _languages: string[]): Promise<RuleMatch[]> {
    return [];
  }
}
