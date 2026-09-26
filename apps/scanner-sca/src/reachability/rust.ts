/**
 * In-process Rust import extraction. No cargo / rustc / rust-analyzer spawn.
 *
 * Crate roots are over-approximated: a local module that looks like a crate
 * only over-reports `reachable`. Missing a real crate root is the failure mode.
 */

/** Prelude roots that are never crates.io packages. */
const RUST_NON_CRATE_ROOTS = new Set(['std', 'core', 'alloc', 'crate', 'self', 'super', 'Self']);

/**
 * Keywords that are themselves a path root (`crate::`, `self::`, `super::`, `Self::`).
 * Every other keyword is a token boundary: `impl ::serde` names `serde`, not `impl`.
 */
const RUST_PATH_KEYWORDS = new Set(['crate', 'self', 'super', 'Self']);

const RUST_KEYWORDS = new Set([
  'as',
  'async',
  'await',
  'break',
  'const',
  'continue',
  'crate',
  'dyn',
  'else',
  'enum',
  'extern',
  'false',
  'fn',
  'for',
  'if',
  'impl',
  'in',
  'let',
  'loop',
  'match',
  'mod',
  'move',
  'mut',
  'pub',
  'ref',
  'return',
  'self',
  'Self',
  'static',
  'struct',
  'super',
  'trait',
  'true',
  'type',
  'unsafe',
  'use',
  'where',
  'while',
  'abstract',
  'become',
  'box',
  'do',
  'final',
  'macro',
  'override',
  'priv',
  'typeof',
  'unsized',
  'virtual',
  'yield',
  'try',
]);

export function isRustSource(fileName: string): boolean {
  return fileName.endsWith('.rs');
}

/**
 * True when a path segment (not the file name) is Cargo build output or a
 * vendored crate tree. First-party reachability must ignore those `.rs` files.
 */
export function isRustBuildOrVendoredPath(relPath: string): boolean {
  const segments = relPath.split('/');
  for (let i = 0; i < segments.length - 1; i += 1) {
    if (segments[i] === 'target' || segments[i] === 'vendor') return true;
  }
  return false;
}

export function extractRustImports(content: string): { packages: string[]; dynamic: boolean } {
  const stripped = stripRustCommentsAndStrings(content);
  const packages = new Set<string>();
  collectPathRoots(stripped, packages);
  collectExternCrates(stripped, packages);
  collectUseImports(stripped, packages);
  return { packages: [...packages], dynamic: hasIncludeMacro(stripped) };
}

/**
 * Cargo dependency rename (`package = "…"`). Any such rename makes Rust
 * ambiguous — this slice does not map aliases, so it must not emit
 * `not_reachable`.
 *
 * Tables: `dependencies`, `dev-dependencies`, `build-dependencies`,
 * `target.*.dependencies`, plus the same rename key under
 * `target.*.dev-dependencies`, `target.*.build-dependencies`, and
 * `workspace.dependencies` (same fail-closed rule).
 */
export function cargoTomlDeclaresDependencyRename(content: string): boolean {
  let inDep = false;
  for (const rawLine of content.split('\n')) {
    const line = stripTomlComment(rawLine).trim();
    if (!line) continue;
    const header = /^\s*\[\[?([^[\]]+)\]\]?\s*$/.exec(line);
    if (header) {
      const arrayTable = /^\s*\[\[/.test(line);
      inDep = !arrayTable && isCargoDependencyTable(header[1] ?? '');
      continue;
    }
    if (inDep && lineDeclaresPackageRename(line)) return true;
    if (assignmentIsDependencyRename(line)) return true;
  }
  return false;
}

/** `include!`, `include! { … }`, and `include![ … ]` all pull in outside source. */
function hasIncludeMacro(source: string): boolean {
  return /\binclude\s*!\s*[({[]/.test(source);
}

function addCrate(packages: Set<string>, ident: string): void {
  const name = ident.startsWith('r#') ? ident.slice(2) : ident;
  if (!name || RUST_NON_CRATE_ROOTS.has(name) || isNonPathKeyword(name)) return;
  packages.add(name);
}

function isNonPathKeyword(name: string): boolean {
  return RUST_KEYWORDS.has(name) && !RUST_PATH_KEYWORDS.has(name);
}

function collectPathRoots(source: string, packages: Set<string>): void {
  let i = 0;
  while (i < source.length) {
    const ident = readIdent(source, i);
    if (!ident) {
      i += 1;
      continue;
    }
    if (isLifetimeOrLabel(source, i)) {
      i += ident.length;
      continue;
    }
    const after = skipWs(source, i + ident.length);
    if (source.startsWith('::', after) && !isPathContinuation(source, i)) {
      addCrate(packages, ident);
    }
    i += ident.length;
  }
}

/**
 * `foo::bar` — `bar` continues `foo`. A leading `::crate` after `->`, `=>`, `>`,
 * `}`, a lifetime, or a non-path keyword is a new crate root. `>` never continues
 * a path (`Vec::<u8>::new` may over-report `new`).
 */
function isPathContinuation(source: string, identStart: number): boolean {
  let j = identStart - 1;
  while (j >= 0 && isWs(source[j]!)) j -= 1;
  if (j < 1 || source[j] !== ':' || source[j - 1] !== ':') return false;
  let k = j - 2;
  while (k >= 0 && isWs(source[k]!)) k -= 1;
  if (k < 0) return false;
  const prev = source[k]!;
  if (prev === '>') return false;
  if (!isIdentCont(prev)) return false;
  const ident = identEndingAt(source, k);
  if (!ident) return false;
  if (isLifetimeOrLabel(source, k - ident.length + 1)) return false;
  const bare = ident.startsWith('r#') ? ident.slice(2) : ident;
  if (RUST_PATH_KEYWORDS.has(bare)) return true;
  if (RUST_KEYWORDS.has(bare)) return false;
  return true;
}

/** `'a` and `'label` are lifetimes or loop labels, never crate roots. */
function isLifetimeOrLabel(source: string, identStart: number): boolean {
  return source[identStart - 1] === "'";
}

function identEndingAt(source: string, end: number): string | undefined {
  let start = end;
  while (start >= 0 && isIdentCont(source[start] ?? '')) start -= 1;
  start += 1;
  if (start > end || !isIdentStart(source[start] ?? '')) return undefined;
  if (
    start >= 2 &&
    source[start - 2] === 'r' &&
    source[start - 1] === '#' &&
    !isIdentCont(source[start - 3] ?? '')
  ) {
    return source.slice(start - 2, end + 1);
  }
  return source.slice(start, end + 1);
}

function collectExternCrates(source: string, packages: Set<string>): void {
  let i = 0;
  while (i < source.length) {
    if (!isKeywordAt(source, i, 'extern')) {
      i += 1;
      continue;
    }
    let j = skipWs(source, i + 'extern'.length);
    if (!isKeywordAt(source, j, 'crate')) {
      i += 'extern'.length;
      continue;
    }
    j = skipWs(source, j + 'crate'.length);
    const ident = readIdent(source, j);
    if (ident) addCrate(packages, ident);
    i = j + (ident?.length ?? 1);
  }
}

function collectUseImports(source: string, packages: Set<string>): void {
  let i = 0;
  while (i < source.length) {
    if (!isKeywordAt(source, i, 'use')) {
      i += 1;
      continue;
    }
    const next = parseUseTree(source, i + 'use'.length, packages, true);
    i = next > i ? next : i + 'use'.length;
  }
}

/**
 * Use-tree roots: `use ident`, `use ::ident`, `use {a, b::c}`.
 * Segments after the first `::` are not crate roots (`use foo::{bar}` → `foo`).
 */
function parseUseTree(source: string, i: number, packages: Set<string>, atRoot: boolean): number {
  let j = skipWs(source, i);
  if (j >= source.length) return j;

  if (source.startsWith('::', j)) {
    j = skipWs(source, j + 2);
  }
  if (source[j] === '{') return parseUseGroup(source, j, packages, atRoot);

  const ident = readIdent(source, j);
  if (!ident) return j + 1;
  if (atRoot) addCrate(packages, ident);
  j = skipWs(source, j + ident.length);
  j = skipAsAlias(source, j);
  if (!source.startsWith('::', j)) return j;

  while (source.startsWith('::', j)) {
    j = skipWs(source, j + 2);
    if (source[j] === '*') {
      j = skipWs(source, j + 1);
      break;
    }
    if (source[j] === '{') {
      j = parseUseGroup(source, j, packages, false);
      break;
    }
    const seg = readIdent(source, j);
    if (!seg) break;
    j = skipWs(source, j + seg.length);
    j = skipAsAlias(source, j);
  }
  return j;
}

function parseUseGroup(source: string, i: number, packages: Set<string>, atRoot: boolean): number {
  let j = i + 1;
  while (j < source.length) {
    j = skipWs(source, j);
    if (j >= source.length) return j;
    if (source[j] === '}') return j + 1;
    if (source[j] === ',') {
      j += 1;
      continue;
    }
    const next = parseUseTree(source, j, packages, atRoot);
    if (next <= j) j += 1;
    else j = next;
  }
  return j;
}

function skipAsAlias(source: string, i: number): number {
  let j = skipWs(source, i);
  if (!isKeywordAt(source, j, 'as')) return j;
  j = skipWs(source, j + 2);
  const alias = readIdent(source, j);
  if (!alias) return j;
  return skipWs(source, j + alias.length);
}

function readIdent(source: string, i: number): string | undefined {
  let j = i;
  if (source.startsWith('r#', j) && isIdentStart(source[j + 2] ?? '')) {
    j += 2;
    while (isIdentCont(source[j] ?? '')) j += 1;
    return source.slice(i, j);
  }
  if (!isIdentStart(source[j] ?? '')) return undefined;
  j += 1;
  while (isIdentCont(source[j] ?? '')) j += 1;
  return source.slice(i, j);
}

function isKeywordAt(text: string, index: number, keyword: string): boolean {
  if (index < 0 || !text.startsWith(keyword, index)) return false;
  const before = text[index - 1];
  const after = text[index + keyword.length];
  if (before && /[A-Za-z0-9_]/.test(before)) return false;
  if (after && /[A-Za-z0-9_]/.test(after)) return false;
  return true;
}

function isIdentStart(ch: string): boolean {
  return /[A-Za-z_]/.test(ch);
}

function isIdentCont(ch: string): boolean {
  return /[A-Za-z0-9_]/.test(ch);
}

function isWs(ch: string): boolean {
  return /\s/.test(ch);
}

function skipWs(source: string, i: number): number {
  let j = i;
  while (j < source.length && isWs(source[j]!)) j += 1;
  return j;
}

function stripRustCommentsAndStrings(source: string): string {
  let out = '';
  let i = 0;
  while (i < source.length) {
    const current = source[i]!;
    const next = source[i + 1];

    if (current === '/' && next === '/') {
      i += 2;
      while (i < source.length && source[i] !== '\n') i += 1;
      out += ' ';
      continue;
    }
    if (current === '/' && next === '*') {
      i = skipBlockComment(source, i);
      out += ' ';
      continue;
    }

    const rawEnd = matchRawString(source, i);
    if (rawEnd !== undefined) {
      i = rawEnd;
      out += ' ';
      continue;
    }

    if (current === '"') {
      i = skipNormalString(source, i);
      out += ' ';
      continue;
    }
    if ((current === 'b' || current === 'c') && next === '"' && !isIdentCont(source[i - 1] ?? '')) {
      i = skipNormalString(source, i + 1);
      out += ' ';
      continue;
    }

    const charEnd = matchCharLiteral(source, i);
    if (charEnd !== undefined) {
      i = charEnd;
      out += ' ';
      continue;
    }

    out += current;
    i += 1;
  }
  return out;
}

function skipBlockComment(source: string, i: number): number {
  let j = i + 2;
  let depth = 1;
  while (j < source.length && depth > 0) {
    if (source[j] === '/' && source[j + 1] === '*') {
      depth += 1;
      j += 2;
      continue;
    }
    if (source[j] === '*' && source[j + 1] === '/') {
      depth -= 1;
      j += 2;
      continue;
    }
    j += 1;
  }
  return j;
}

/** `r"…"`, `r#"…"#`, `br#"…"#`, `cr##"…"##` when the prefix is not an ident. */
function matchRawString(source: string, i: number): number | undefined {
  let j = i;
  const prev = source[i - 1] ?? '';
  if ((source[j] === 'b' || source[j] === 'c') && source[j + 1] === 'r') {
    if (isIdentCont(prev)) return undefined;
    j += 2;
  } else if (source[j] === 'r') {
    if (isIdentCont(prev)) return undefined;
    j += 1;
  } else {
    return undefined;
  }

  let hashes = 0;
  while (source[j] === '#') {
    hashes += 1;
    j += 1;
  }
  if (source[j] !== '"') return undefined;
  j += 1;
  const closer = `"${'#'.repeat(hashes)}`;
  const end = source.indexOf(closer, j);
  if (end === -1) return source.length;
  return end + closer.length;
}

function skipNormalString(source: string, i: number): number {
  let j = i + 1;
  while (j < source.length) {
    if (source[j] === '\\') {
      j += 2;
      continue;
    }
    if (source[j] === '"') return j + 1;
    j += 1;
  }
  return source.length;
}

function matchCharLiteral(source: string, i: number): number | undefined {
  let j = i;
  if (source[j] === 'b' && source[j + 1] === "'" && !isIdentCont(source[j - 1] ?? '')) j += 1;
  if (source[j] !== "'") return undefined;
  j += 1;
  if (j >= source.length) return undefined;
  if (source[j] === '\\') {
    j += 1;
    if (source[j] === 'u' && source[j + 1] === '{') {
      j += 2;
      while (j < source.length && source[j] !== '}') j += 1;
      if (source[j] !== '}') return undefined;
      j += 1;
      return source[j] === "'" ? j + 1 : undefined;
    }
    if (source[j] === 'x') {
      j += 1;
      if (isHex(source[j] ?? '')) j += 1;
      if (isHex(source[j] ?? '')) j += 1;
      return source[j] === "'" ? j + 1 : undefined;
    }
    j += 1;
    return source[j] === "'" ? j + 1 : undefined;
  }
  if (source[j + 1] === "'") return j + 2;
  return undefined;
}

function isHex(ch: string): boolean {
  return /[0-9A-Fa-f]/.test(ch);
}

function isCargoDependencyTable(header: string): boolean {
  const parts = splitTomlHeader(header);
  if (parts.length === 0) return false;
  const root = parts[0];
  if (root === 'dependencies' || root === 'dev-dependencies' || root === 'build-dependencies') {
    return true;
  }
  if (root === 'target') {
    return parts.some(
      (part) =>
        part === 'dependencies' || part === 'dev-dependencies' || part === 'build-dependencies',
    );
  }
  if (root === 'workspace' && parts.includes('dependencies')) return true;
  return false;
}

function splitTomlHeader(header: string): string[] {
  const parts: string[] = [];
  let i = 0;
  while (i < header.length) {
    while (i < header.length && (header[i] === '.' || header[i] === ' ' || header[i] === '\t')) {
      i += 1;
    }
    if (i >= header.length) break;
    const quote = header[i];
    if (quote === '"' || quote === "'") {
      i += 1;
      let value = '';
      while (i < header.length && header[i] !== quote) {
        value += header[i];
        i += 1;
      }
      i += 1;
      parts.push(value);
      continue;
    }
    let value = '';
    while (i < header.length && header[i] !== '.' && header[i] !== ' ' && header[i] !== '\t') {
      value += header[i];
      i += 1;
    }
    if (value) parts.push(value);
  }
  return parts;
}

function assignmentIsDependencyRename(line: string): boolean {
  const key = readTomlKeyPath(line);
  if (!key || !isCargoDependencyTable(key)) return false;
  return lineDeclaresPackageRename(line);
}

function readTomlKeyPath(line: string): string | undefined {
  let i = 0;
  while (i < line.length) {
    const current = line[i]!;
    if (current === '"' || current === "'") {
      i = skipTomlString(line, i);
      continue;
    }
    if (current === '=') return line.slice(0, i).trim();
    i += 1;
  }
  return undefined;
}

function lineDeclaresPackageRename(line: string): boolean {
  let i = 0;
  while (i < line.length) {
    const current = line[i]!;
    if (current === '"' || current === "'") {
      const end = skipTomlString(line, i);
      const raw = line[end - 1] === current ? line.slice(i + 1, end - 1) : '';
      if (raw === 'package' && packageValueFollows(line, end)) return true;
      i = end;
      continue;
    }
    if (isTomlKeyAt(line, i, 'package')) {
      if (packageValueFollows(line, i + 'package'.length)) return true;
      i += 'package'.length;
      continue;
    }
    i += 1;
  }
  return false;
}

function packageValueFollows(line: string, afterKey: number): boolean {
  let j = skipWsIndex(line, afterKey);
  if (line[j] !== '=') return false;
  j = skipWsIndex(line, j + 1);
  const quote = line[j];
  return (quote === '"' || quote === "'") && skipTomlString(line, j) > j + 2;
}

function isTomlKeyAt(line: string, index: number, key: string): boolean {
  if (!line.startsWith(key, index)) return false;
  const before = line[index - 1];
  const after = line[index + key.length];
  if (before && /[A-Za-z0-9_-]/.test(before)) return false;
  if (after && /[A-Za-z0-9_-]/.test(after)) return false;
  return true;
}

function skipTomlString(line: string, i: number): number {
  const quote = line[i];
  let j = i + 1;
  while (j < line.length) {
    if (line[j] === '\\') {
      j += 2;
      continue;
    }
    if (line[j] === quote) return j + 1;
    j += 1;
  }
  return line.length;
}

function stripTomlComment(line: string): string {
  let out = '';
  let quote: string | undefined;
  for (let i = 0; i < line.length; i += 1) {
    const current = line[i]!;
    if (quote) {
      out += current;
      if (current === '\\') {
        i += 1;
        if (i < line.length) out += line[i];
        continue;
      }
      if (current === quote) quote = undefined;
      continue;
    }
    if (current === '"' || current === "'") {
      quote = current;
      out += current;
      continue;
    }
    if (current === '#') break;
    out += current;
  }
  return out;
}

function skipWsIndex(text: string, i: number): number {
  let j = i;
  while (j < text.length && isWs(text[j]!)) j += 1;
  return j;
}
