export type SastLanguage = 'javascript' | 'typescript' | 'python';

const JS_EXT = /\.[cm]?jsx?$/;
const TS_EXT = /\.tsx?$/;

export function languageOf(fileName: string): SastLanguage | undefined {
  if (fileName.endsWith('.d.ts')) return undefined;
  if (TS_EXT.test(fileName)) return 'typescript';
  if (JS_EXT.test(fileName)) return 'javascript';
  if (fileName.endsWith('.py')) return 'python';
  return undefined;
}

export function lineAt(source: string, index: number): number {
  let line = 1;
  const limit = Math.min(index, source.length);
  for (let i = 0; i < limit; i += 1) {
    if (source[i] === '\n') line += 1;
  }
  return line;
}

export function lineSnippet(source: string, line: number): string {
  const lines = source.split('\n');
  return (lines[line - 1] ?? '').trim().slice(0, 200);
}

export function skipQuoted(source: string, start: number): number {
  const quote = source[start];
  let i = start + 1;
  while (i < source.length) {
    if (quote !== '`' && source[i] === '\\') {
      i += 2;
      continue;
    }
    if (source[i] === quote) return i + 1;
    i += 1;
  }
  return source.length;
}

/** Replace comments with spaces so line/column offsets stay aligned. */
export function stripCommentsPreserve(source: string, language: SastLanguage): string {
  return language === 'python' ? stripPyCommentsPreserve(source) : stripJsCommentsPreserve(source);
}

function stripJsCommentsPreserve(source: string): string {
  let out = '';
  let i = 0;
  while (i < source.length) {
    const current = source[i];
    const next = source[i + 1];

    if (current === '"' || current === "'" || current === '`') {
      const end = skipQuoted(source, i);
      out += source.slice(i, end);
      i = end;
      continue;
    }

    if (current === '/' && next === '/') {
      i += 2;
      out += '  ';
      while (i < source.length && source[i] !== '\n') {
        out += ' ';
        i += 1;
      }
      continue;
    }

    if (current === '/' && next === '*') {
      out += '  ';
      i += 2;
      while (i + 1 < source.length && !(source[i] === '*' && source[i + 1] === '/')) {
        out += source[i] === '\n' ? '\n' : ' ';
        i += 1;
      }
      if (i + 1 < source.length) {
        out += '  ';
        i += 2;
      }
      continue;
    }

    out += current;
    i += 1;
  }
  return out;
}

function stripPyCommentsPreserve(source: string): string {
  let out = '';
  let i = 0;
  let quote: string | undefined;
  while (i < source.length) {
    const current = source[i];
    if (quote) {
      out += current;
      if (current === '\\') {
        i += 1;
        if (i < source.length) {
          out += source[i];
          i += 1;
        }
        continue;
      }
      if (current === quote) quote = undefined;
      i += 1;
      continue;
    }
    if (current === "'" || current === '"') {
      quote = current;
      out += current;
      i += 1;
      continue;
    }
    if (current === '#') {
      while (i < source.length && source[i] !== '\n') {
        out += ' ';
        i += 1;
      }
      continue;
    }
    out += current;
    i += 1;
  }
  return out;
}

export interface CallHit {
  name: string;
  qualified: string;
  args: string;
  index: number;
  line: number;
}

export function findCalls(source: string): CallHit[] {
  const hits: CallHit[] = [];
  let i = 0;
  while (i < source.length) {
    const current = source[i];
    if (current === '"' || current === "'" || current === '`') {
      i = skipQuoted(source, i);
      continue;
    }
    if (current && /[A-Za-z_]/.test(current)) {
      const start = i;
      i += 1;
      while (i < source.length && /[\w.]/.test(source[i]!)) i += 1;
      const qualified = source.slice(start, i);
      let j = i;
      while (j < source.length && /\s/.test(source[j]!)) j += 1;
      if (source[j] === '(') {
        const close = matchingParen(source, j);
        hits.push({
          name: qualified.split('.').pop() ?? qualified,
          qualified,
          args: source.slice(j + 1, close),
          index: start,
          line: lineAt(source, start),
        });
        // Stay inside the argument list so nested calls (db.query inside
        // app.get) are still recorded.
        i = j + 1;
        continue;
      }
      continue;
    }
    i += 1;
  }
  return hits;
}

export function matchingParen(source: string, open: number): number {
  let depth = 0;
  let i = open;
  while (i < source.length) {
    const current = source[i];
    if (current === '"' || current === "'" || current === '`') {
      i = skipQuoted(source, i);
      continue;
    }
    if (current === '(') depth += 1;
    else if (current === ')') {
      depth -= 1;
      if (depth === 0) return i;
    }
    i += 1;
  }
  return source.length;
}

export function firstArg(args: string): string {
  let depth = 0;
  let quote: string | undefined;
  for (let i = 0; i < args.length; i += 1) {
    const current = args[i];
    if (quote) {
      if (current === '\\' && quote !== '`') {
        i += 1;
        continue;
      }
      if (current === quote) quote = undefined;
      continue;
    }
    if (current === '"' || current === "'" || current === '`') {
      quote = current;
      continue;
    }
    if (current === '(' || current === '[' || current === '{') depth += 1;
    else if (current === ')' || current === ']' || current === '}') depth -= 1;
    else if (current === ',' && depth === 0) return args.slice(0, i);
  }
  return args;
}

/** Concatenation, interpolation, or a bare identifier — not a string literal or argv array. */
export function isInterpolatedArg(arg: string, language: SastLanguage): boolean {
  const trimmed = arg.trim();
  if (!trimmed) return false;
  if (/\$\{/.test(trimmed)) return true;
  if (/\+/.test(trimmed) && /['"`]/.test(trimmed)) return true;
  if (language === 'python') {
    if (/^f['"]/i.test(trimmed) || /^f'''/i.test(trimmed)) return true;
    // `"..." % var` is interpolation. `%s` inside a parameterized literal is not.
    if (/['"][^'"]*['"]\s*%/.test(trimmed)) return true;
    if (/\.format\s*\(/.test(trimmed)) return true;
  }
  if (isSingleStringLiteral(trimmed)) return false;
  return /^[A-Za-z_][\w.]*$/.test(trimmed);
}

export function isSingleStringLiteral(expr: string): boolean {
  const t = expr.trim();
  if (t.length < 2) return false;
  const quote = t[0];
  if (quote !== '"' && quote !== "'" && quote !== '`') return false;
  if (t[t.length - 1] !== quote) return false;
  if (quote === '`' && t.includes('${')) return false;
  return true;
}

export function isWordAt(source: string, index: number, word: string): boolean {
  if (!source.startsWith(word, index)) return false;
  const before = source[index - 1];
  const after = source[index + word.length];
  if (before && /[A-Za-z0-9_$]/.test(before)) return false;
  if (after && /[A-Za-z0-9_$]/.test(after)) return false;
  return true;
}
