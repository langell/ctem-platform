import { normalizePyName } from './types';

export function isPythonSource(fileName: string): boolean {
  return fileName.endsWith('.py');
}

export function extractPyImports(source: string): { packages: string[]; dynamic: boolean } {
  const stripped = stripPyComments(source);
  const dynamic =
    /\bimportlib\.import_module\s*\(\s*(?!['"])/.test(stripped) ||
    /\b__import__\s*\(\s*(?!['"])/.test(stripped);

  const packages = new Set<string>();

  for (const raw of stripped.split('\n')) {
    const line = raw.trim();
    const from = /^from\s+(\S+)\s+import\b/.exec(line);
    if (from) {
      const name = topLevelPyModule(from[1]);
      if (name) packages.add(normalizePyName(name));
      continue;
    }
    const direct = /^import\s+(.+)$/.exec(line);
    if (!direct) continue;
    for (const part of direct[1].split(',')) {
      const name = topLevelPyModule(part.trim().split(/\s+as\s+/)[0] ?? '');
      if (name) packages.add(normalizePyName(name));
    }
  }

  return { packages: [...packages], dynamic };
}

function topLevelPyModule(spec: string): string | undefined {
  if (!spec || spec.startsWith('.')) return undefined;
  const name = spec.split('.')[0];
  if (!name || name === '__future__') return undefined;
  return name;
}

function stripPyComments(source: string): string {
  return source
    .split('\n')
    .map((line) => {
      let out = '';
      let i = 0;
      let quote: string | undefined;
      while (i < line.length) {
        const current = line[i];
        if (quote) {
          out += current;
          if (current === '\\') {
            i += 1;
            if (i < line.length) {
              out += line[i];
              i += 1;
            }
            continue;
          }
          if (current === quote) quote = undefined;
          i += 1;
          continue;
        }
        if (current === '#' ) break;
        if (current === "'" || current === '"') quote = current;
        out += current;
        i += 1;
      }
      return out;
    })
    .join('\n');
}
