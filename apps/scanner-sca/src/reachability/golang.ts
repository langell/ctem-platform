export function isGoSource(fileName: string): boolean {
  return fileName.endsWith('.go');
}

export function extractGoImports(source: string): { packages: string[]; dynamic: boolean } {
  const stripped = stripGoComments(source);
  const packages = new Set<string>();
  const importBlock = /\bimport\s*\(([^)]*)\)/g;
  let match: RegExpExecArray | null;
  while ((match = importBlock.exec(stripped))) {
    for (const line of match[1].split('\n')) {
      const path = goImportPath(line);
      if (path) packages.add(path);
    }
  }

  const single = /\bimport\s+(?:[A-Za-z_]\w*\s+)?["`]([^"`]+)["`]/g;
  while ((match = single.exec(stripped))) {
    const path = match[1];
    if (path && isThirdPartyGo(path)) packages.add(path);
  }

  return { packages: [...packages], dynamic: false };
}

function goImportPath(line: string): string | undefined {
  const match = /["`]([^"`]+)["`]/.exec(line);
  const path = match?.[1];
  if (!path || !isThirdPartyGo(path)) return undefined;
  return path;
}

/** Stdlib paths have no dot in the first element (`fmt`, `net/http`). */
function isThirdPartyGo(path: string): boolean {
  if (path === 'C') return false;
  const first = path.split('/')[0] ?? '';
  return first.includes('.');
}

function stripGoComments(source: string): string {
  let out = '';
  let i = 0;
  while (i < source.length) {
    const current = source[i];
    const next = source[i + 1];
    if (current === '"' || current === '`' || current === "'") {
      const quote = current;
      out += current;
      i += 1;
      while (i < source.length) {
        out += source[i];
        if (quote !== '`' && source[i] === '\\') {
          i += 1;
          if (i < source.length) {
            out += source[i];
            i += 1;
          }
          continue;
        }
        if (source[i] === quote) {
          i += 1;
          break;
        }
        i += 1;
      }
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
