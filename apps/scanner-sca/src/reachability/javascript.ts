/** In-process JS/TS import extraction. No node_modules walk, no npm spawn. */

const JS_EXT = /\.(?:[cm]?[jt]sx?)$/;

export function isJavascriptSource(fileName: string): boolean {
  if (fileName.endsWith('.d.ts')) return false;
  return JS_EXT.test(fileName);
}

export function npmPackageName(specifier: string): string | undefined {
  if (!specifier || specifier.startsWith('.') || specifier.startsWith('/') || specifier.startsWith('node:')) {
    return undefined;
  }
  if (specifier.startsWith('@')) {
    const parts = specifier.split('/');
    if (parts.length < 2 || !parts[1]) return undefined;
    return `${parts[0]}/${parts[1]}`;
  }
  const name = specifier.split('/')[0];
  return name || undefined;
}

/**
 * Keyword-driven scan so `import` inside a string or comment cannot mint a
 * reachable verdict. Dynamic `require(x)` / `import(x)` is reported separately.
 */
export function extractJsImports(source: string): { packages: string[]; dynamic: boolean } {
  const text = stripJsCommentsAndKeepStrings(source);
  const packages = new Set<string>();
  let dynamic = false;
  let i = 0;

  while (i < text.length) {
    const current = text[i];
    if (current === '"' || current === "'" || current === '`') {
      i = skipQuoted(text, i);
      continue;
    }

    if (isKeywordAt(text, i, 'require')) {
      const spec = readCallSpecifier(text, i + 'require'.length);
      if (spec === 'dynamic') dynamic = true;
      else if (spec) addPackage(packages, spec);
      i += 'require'.length;
      continue;
    }

    if (isKeywordAt(text, i, 'import')) {
      const after = i + 'import'.length;
      if (isCallOpen(text, after)) {
        const spec = readCallSpecifier(text, after);
        if (spec === 'dynamic') dynamic = true;
        else if (spec) addPackage(packages, spec);
      } else {
        const spec = readStaticSpecifier(text, after);
        if (spec) addPackage(packages, spec);
      }
      i = after;
      continue;
    }

    if (isKeywordAt(text, i, 'export')) {
      const spec = readStaticSpecifier(text, i + 'export'.length);
      if (spec) addPackage(packages, spec);
      i += 'export'.length;
      continue;
    }

    i += 1;
  }

  return { packages: [...packages], dynamic };
}

function addPackage(packages: Set<string>, specifier: string): void {
  const name = npmPackageName(specifier);
  if (name) packages.add(name);
}

function isKeywordAt(text: string, index: number, keyword: string): boolean {
  if (!text.startsWith(keyword, index)) return false;
  const before = text[index - 1];
  const after = text[index + keyword.length];
  if (before && /[A-Za-z0-9_$]/.test(before)) return false;
  if (after && /[A-Za-z0-9_$]/.test(after)) return false;
  return true;
}

function isCallOpen(text: string, index: number): boolean {
  let i = index;
  while (i < text.length && /\s/.test(text[i]!)) i += 1;
  return text[i] === '(';
}

function readCallSpecifier(text: string, afterKeyword: number): string | 'dynamic' | undefined {
  let i = afterKeyword;
  while (i < text.length && /\s/.test(text[i]!)) i += 1;
  if (text[i] !== '(') return undefined;
  i += 1;
  while (i < text.length && /\s/.test(text[i]!)) i += 1;
  const quote = text[i];
  if (quote === '"' || quote === "'" || quote === '`') {
    const end = skipQuoted(text, i);
    const raw = text.slice(i + 1, end - 1);
    if (quote === '`' && raw.includes('${')) return 'dynamic';
    return raw;
  }
  return 'dynamic';
}

function readStaticSpecifier(text: string, afterKeyword: number): string | undefined {
  const limit = Math.min(text.length, afterKeyword + 800);
  let i = afterKeyword;
  while (i < limit && /\s/.test(text[i]!)) i += 1;
  if (text[i] === '"' || text[i] === "'") {
    const end = skipQuoted(text, i);
    return text.slice(i + 1, end - 1);
  }

  while (i < limit) {
    const current = text[i];
    if (current === '"' || current === "'" || current === '`') {
      i = skipQuoted(text, i);
      continue;
    }
    if (isKeywordAt(text, i, 'from')) {
      let j = i + 'from'.length;
      while (j < limit && /\s/.test(text[j]!)) j += 1;
      if (text[j] === '"' || text[j] === "'") {
        const end = skipQuoted(text, j);
        return text.slice(j + 1, end - 1);
      }
      return undefined;
    }
    if (current === ';' ) return undefined;
    i += 1;
  }
  return undefined;
}

/**
 * Drop // and /* * / comments without touching string contents, so an
 * `import` inside a comment cannot mint a reachable verdict.
 */
export function stripJsCommentsAndKeepStrings(source: string): string {
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
      while (i < source.length && source[i] !== '\n') i += 1;
      continue;
    }

    if (current === '/' && next === '*') {
      i += 2;
      while (i + 1 < source.length && !(source[i] === '*' && source[i + 1] === '/')) i += 1;
      i = Math.min(i + 2, source.length);
      out += ' ';
      continue;
    }

    out += current;
    i += 1;
  }
  return out;
}

function skipQuoted(source: string, start: number): number {
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
