import type { SastCallSite, SastTaintFlow } from './graph';
import {
  findCalls,
  firstArg,
  isInterpolatedArg,
  isWordAt,
  skipQuoted,
  stripCommentsPreserve,
  type SastLanguage,
} from './source';

export interface FileGraph {
  imports: Set<string>;
  calls: SastCallSite[];
  taintFlows: SastTaintFlow[];
  tainted: Map<string, { line: number; kind: string }>;
}

const JS_SOURCES = [
  'req.query',
  'req.body',
  'req.params',
  'req.headers',
  'req.cookies',
  'request.query',
  'request.body',
  'request.params',
  'ctx.query',
  'ctx.params',
  'ctx.request.body',
  'process.argv',
];

const PY_SOURCES = ['request.args', 'request.form', 'request.values', 'request.json', 'request.GET', 'request.POST', 'request.data', 'sys.argv'];

const SQL_SINKS = new Set(['query', 'execute', 'executemany']);
const CMD_SINKS = new Set(['exec', 'execsync', 'system', 'popen']);
const CMD_QUALIFIED = new Set([
  'os.system',
  'os.popen',
  'subprocess.call',
  'subprocess.run',
  'subprocess.popen',
  'child_process.exec',
  'child_process.execsync',
]);

export function analyzeFile(relPath: string, content: string, language: SastLanguage): FileGraph {
  const text = stripCommentsPreserve(content, language);
  const tainted = new Map<string, { line: number; kind: string }>();
  collectAssignments(text, language, tainted);
  const imports = extractImports(text, language);
  const calls: SastCallSite[] = [];
  const taintFlows: SastTaintFlow[] = [];

  for (const hit of findCalls(text)) {
    calls.push({ path: relPath, line: hit.line, callee: hit.qualified });
    const sink = sinkKind(hit.qualified, hit.name);
    if (!sink) continue;
    const arg = firstArg(hit.args);
    if (!isInterpolatedArg(arg, language) && !exprIsTainted(arg, tainted, language)) continue;
    if (sink === 'command' && !isInterpolatedArg(arg, language)) continue;
    const source = taintOf(arg, tainted, language);
    if (!source) continue;
    const sourceLine = source.line > 0 ? source.line : hit.line;
    taintFlows.push({
      source: { path: relPath, line: sourceLine, kind: source.kind },
      sink: { path: relPath, line: hit.line, kind: sink },
      path: [
        { path: relPath, line: sourceLine, label: 'source' },
        { path: relPath, line: hit.line, label: 'sink' },
      ],
    });
  }

  return { imports, calls, taintFlows, tainted };
}

export function mergeFileGraph(
  into: { imports: Map<string, Set<string>>; calls: SastCallSite[]; taintFlows: SastTaintFlow[] },
  relPath: string,
  file: FileGraph,
): void {
  into.imports.set(relPath, file.imports);
  into.calls.push(...file.calls);
  into.taintFlows.push(...file.taintFlows);
}

export function exprIsTainted(
  expr: string,
  tainted: Map<string, { line: number; kind: string }>,
  language: SastLanguage,
): boolean {
  return taintOf(expr, tainted, language) !== undefined;
}

export function taintOf(
  expr: string,
  tainted: Map<string, { line: number; kind: string }>,
  language: SastLanguage,
): { line: number; kind: string } | undefined {
  const sources = language === 'python' ? PY_SOURCES : JS_SOURCES;
  for (const kind of sources) {
    if (expr.includes(kind)) return { line: 0, kind };
  }
  if (language === 'python' && /\binput\s*\(/.test(expr)) return { line: 0, kind: 'input()' };
  for (const [name, info] of tainted) {
    if (isIdentInExpr(expr, name)) return info;
  }
  return undefined;
}

function collectAssignments(
  text: string,
  language: SastLanguage,
  tainted: Map<string, { line: number; kind: string }>,
): void {
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i] ?? '';
    const lineNo = i + 1;
    const destruct = /(?:const|let|var)\s*\{([^}]+)\}\s*=\s*(.+)/.exec(line);
    if (destruct) {
      const source = taintOf(destruct[2] ?? '', tainted, language);
      if (source) {
        for (const raw of (destruct[1] ?? '').split(',')) {
          const name = raw.trim().split(':')[0]?.trim();
          if (name) tainted.set(name, { line: lineNo, kind: source.kind });
        }
      }
      continue;
    }
    const assign =
      language === 'python'
        ? /^\s*([A-Za-z_][\w]*)\s*=\s*(.+)$/.exec(line)
        : /^(?:const|let|var)\s+([A-Za-z_][\w]*)\s*=\s*(.+)$/.exec(line.trim()) ??
          /^([A-Za-z_][\w]*)\s*=\s*(.+)$/.exec(line.trim());
    if (!assign) continue;
    const source = taintOf(assign[2] ?? '', tainted, language);
    if (source) tainted.set(assign[1] ?? '', { line: lineNo, kind: source.kind });
  }
}

function sinkKind(qualified: string, name: string): string | undefined {
  const q = qualified.toLowerCase();
  const n = name.toLowerCase();
  if (n === 'execfile') return undefined;
  if (SQL_SINKS.has(n)) return 'sql';
  if (CMD_QUALIFIED.has(q) || CMD_SINKS.has(n)) return 'command';
  return undefined;
}

function isIdentInExpr(expr: string, name: string): boolean {
  const re = new RegExp(`(?:^|[^A-Za-z0-9_$])${escapeRegExp(name)}(?:[^A-Za-z0-9_$]|$)`);
  return re.test(expr);
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function extractImports(text: string, language: SastLanguage): Set<string> {
  return language === 'python' ? extractPyImports(text) : extractJsImports(text);
}

function extractJsImports(text: string): Set<string> {
  const specs = new Set<string>();
  let i = 0;
  while (i < text.length) {
    const current = text[i];
    if (current === '"' || current === "'" || current === '`') {
      i = skipQuoted(text, i);
      continue;
    }
    if (isWordAt(text, i, 'import') || isWordAt(text, i, 'require') || isWordAt(text, i, 'from')) {
      const word = text.startsWith('require', i) ? 'require' : text.startsWith('import', i) ? 'import' : 'from';
      let j = i + word.length;
      while (j < text.length && /\s/.test(text[j]!)) j += 1;
      if (text[j] === '(' || text[j] === '"' || text[j] === "'") {
        const quotePos = text[j] === '(' ? skipWs(text, j + 1) : j;
        if (text[quotePos] === '"' || text[quotePos] === "'") {
          const end = skipQuoted(text, quotePos);
          const spec = text.slice(quotePos + 1, end - 1);
          if (spec) specs.add(spec);
        }
      }
      i += word.length;
      continue;
    }
    i += 1;
  }
  return specs;
}

function extractPyImports(text: string): Set<string> {
  const specs = new Set<string>();
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    const from = /^from\s+(\S+)\s+import\b/.exec(line);
    if (from?.[1] && !from[1].startsWith('.')) specs.add(from[1].split('.')[0] ?? from[1]);
    const direct = /^import\s+(.+)$/.exec(line);
    if (!direct) continue;
    for (const part of direct[1].split(',')) {
      const name = part.trim().split(/\s+as\s+/)[0]?.split('.')[0];
      if (name) specs.add(name);
    }
  }
  return specs;
}

function skipWs(text: string, index: number): number {
  let i = index;
  while (i < text.length && /\s/.test(text[i]!)) i += 1;
  return i;
}
