export type HclValue = string | number | boolean | null | HclValue[] | { [key: string]: HclValue };

export interface HclResource {
  type: string;
  name: string;
  address: string;
  attributes: Record<string, HclValue>;
  startLine: number;
}

export class HclParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'HclParseError';
  }
}

type Tok =
  | { kind: 'ident'; value: string; line: number }
  | { kind: 'string'; value: string; line: number }
  | { kind: 'number'; value: number; line: number }
  | { kind: 'punct'; value: string; line: number };

/**
 * In-process HCL subset: `resource "type" "name" { ... }` plus nested blocks
 * and collections. Does not fetch modules, providers, or registries.
 */
export function parseHclResources(content: string): HclResource[] {
  const tokens = tokenize(content);
  const resources: HclResource[] = [];
  let i = 0;

  while (i < tokens.length) {
    const tok = tokens[i];
    if (tok?.kind === 'ident' && tok.value === 'resource') {
      const typeTok = tokens[i + 1];
      const nameTok = tokens[i + 2];
      const brace = tokens[i + 3];
      if (typeTok?.kind !== 'string' || nameTok?.kind !== 'string' || brace?.kind !== 'punct' || brace.value !== '{') {
        throw new HclParseError(`Malformed resource block at line ${tok.line}`);
      }
      const { value: body, next } = parseObject(tokens, i + 4);
      resources.push({
        type: typeTok.value,
        name: nameTok.value,
        address: `${typeTok.value}.${nameTok.value}`,
        attributes: body,
        startLine: tok.line,
      });
      i = next;
      continue;
    }
    if (tok?.kind === 'ident' && (tok.value === 'module' || tok.value === 'data' || tok.value === 'provider')) {
      // Skip — never fetch module/registry sources (SSRF).
      const braceAt = findBrace(tokens, i);
      if (braceAt === -1) throw new HclParseError(`Unclosed ${tok.value} block at line ${tok.line}`);
      const { next } = parseObject(tokens, braceAt + 1);
      i = next;
      continue;
    }
    i += 1;
  }

  return resources;
}

export function parseTfJsonResources(content: string): HclResource[] {
  let doc: unknown;
  try {
    doc = JSON.parse(content) as unknown;
  } catch (err) {
    throw new HclParseError(`Invalid Terraform JSON: ${err instanceof Error ? err.message : String(err)}`);
  }
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) {
    throw new HclParseError('Terraform JSON root must be an object');
  }
  const resource = (doc as Record<string, unknown>).resource;
  if (!resource || typeof resource !== 'object' || Array.isArray(resource)) return [];
  const out: HclResource[] = [];
  for (const [type, names] of Object.entries(resource as Record<string, unknown>)) {
    if (!names || typeof names !== 'object' || Array.isArray(names)) continue;
    for (const [name, body] of Object.entries(names as Record<string, unknown>)) {
      out.push({
        type,
        name,
        address: `${type}.${name}`,
        attributes: asHclObject(body),
        startLine: 1,
      });
    }
  }
  return out;
}

function asHclObject(value: unknown): Record<string, HclValue> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {};
  const out: Record<string, HclValue> = {};
  for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
    out[key] = asHclValue(entry);
  }
  return out;
}

function asHclValue(value: unknown): HclValue {
  if (value === null) return null;
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') return value;
  if (Array.isArray(value)) return value.map(asHclValue);
  if (typeof value === 'object') return asHclObject(value);
  return String(value);
}

function findBrace(tokens: Tok[], from: number): number {
  for (let i = from; i < tokens.length; i += 1) {
    if (tokens[i]?.kind === 'punct' && tokens[i]?.value === '{') return i;
  }
  return -1;
}

function parseObject(tokens: Tok[], start: number): { value: Record<string, HclValue>; next: number } {
  const obj: Record<string, HclValue> = {};
  let i = start;
  while (i < tokens.length) {
    const tok = tokens[i];
    if (tok?.kind === 'punct' && tok.value === '}') return { value: obj, next: i + 1 };
    if (tok?.kind !== 'ident') {
      throw new HclParseError(`Expected identifier in block at line ${tok?.line ?? '?'}`);
    }
    const key = tok.value;
    const next = tokens[i + 1];
    if (next?.kind === 'punct' && next.value === '=') {
      const parsed = parseValue(tokens, i + 2);
      obj[key] = parsed.value;
      i = parsed.next;
      continue;
    }
    // Nested block: key "label"? { ... }
    const labels: string[] = [];
    let j = i + 1;
    while (tokens[j]?.kind === 'string') {
      labels.push((tokens[j] as { value: string }).value);
      j += 1;
    }
    if (tokens[j]?.kind !== 'punct' || tokens[j]?.value !== '{') {
      throw new HclParseError(`Expected '{' after block '${key}' at line ${tok.line}`);
    }
    const nested = parseObject(tokens, j + 1);
    const record: Record<string, HclValue> = { ...nested.value };
    if (labels.length) record.__labels = labels;
    const existing = obj[key];
    if (existing === undefined) obj[key] = [record];
    else if (Array.isArray(existing)) existing.push(record);
    else obj[key] = [existing, record];
    i = nested.next;
  }
  throw new HclParseError('Unclosed HCL block');
}

function parseValue(tokens: Tok[], start: number): { value: HclValue; next: number } {
  const tok = tokens[start];
  if (!tok) throw new HclParseError('Unexpected end of HCL while reading a value');
  if (tok.kind === 'string') return { value: tok.value, next: start + 1 };
  if (tok.kind === 'number') return { value: tok.value, next: start + 1 };
  if (tok.kind === 'ident') {
    if (tok.value === 'true') return { value: true, next: start + 1 };
    if (tok.value === 'false') return { value: false, next: start + 1 };
    if (tok.value === 'null') return { value: null, next: start + 1 };
    // Reference expression (`aws_s3_bucket.logs.id`) — keep as string, never resolve remotely.
    let i = start + 1;
    let text = tok.value;
    while (
      tokens[i]?.kind === 'punct' &&
      (tokens[i]?.value === '.' || tokens[i]?.value === '[')
    ) {
      text += tokens[i]!.value;
      i += 1;
      const part = tokens[i];
      if (part?.kind === 'ident' || part?.kind === 'string' || part?.kind === 'number') {
        text += part.kind === 'string' ? part.value : String(part.value);
        i += 1;
      }
      if (tokens[i - 1]?.kind === 'punct' && tokens[i - 1]?.value === '[') {
        if (tokens[i]?.kind === 'punct' && tokens[i]?.value === ']') i += 1;
      }
    }
    return { value: text, next: i };
  }
  if (tok.kind === 'punct' && tok.value === '[') return parseList(tokens, start + 1);
  if (tok.kind === 'punct' && tok.value === '{') {
    const obj = parseObject(tokens, start + 1);
    return { value: obj.value, next: obj.next };
  }
  throw new HclParseError(`Unexpected token '${tok.kind}' at line ${tok.line}`);
}

function parseList(tokens: Tok[], start: number): { value: HclValue[]; next: number } {
  const items: HclValue[] = [];
  let i = start;
  while (i < tokens.length) {
    const tok = tokens[i];
    if (tok?.kind === 'punct' && tok.value === ']') return { value: items, next: i + 1 };
    if (tok?.kind === 'punct' && tok.value === ',') {
      i += 1;
      continue;
    }
    const parsed = parseValue(tokens, i);
    items.push(parsed.value);
    i = parsed.next;
  }
  throw new HclParseError('Unclosed HCL list');
}

function tokenize(source: string): Tok[] {
  const tokens: Tok[] = [];
  let i = 0;
  let line = 1;

  const push = (tok: Tok) => tokens.push(tok);

  while (i < source.length) {
    const ch = source[i]!;

    if (ch === '\n') {
      line += 1;
      i += 1;
      continue;
    }
    if (ch === ' ' || ch === '\t' || ch === '\r') {
      i += 1;
      continue;
    }
    if (ch === '#' || (ch === '/' && source[i + 1] === '/')) {
      while (i < source.length && source[i] !== '\n') i += 1;
      continue;
    }
    if (ch === '/' && source[i + 1] === '*') {
      i += 2;
      while (i < source.length && !(source[i] === '*' && source[i + 1] === '/')) {
        if (source[i] === '\n') line += 1;
        i += 1;
      }
      i += 2;
      continue;
    }
    if (ch === '"' || ch === "'") {
      const { value, next, line: nextLine } = readString(source, i, line);
      push({ kind: 'string', value, line });
      line = nextLine;
      i = next;
      continue;
    }
    if (ch === '<' && source[i + 1] === '<') {
      const { value, next, line: nextLine } = readHeredoc(source, i, line);
      push({ kind: 'string', value, line });
      line = nextLine;
      i = next;
      continue;
    }
    if (ch === '-' || (ch >= '0' && ch <= '9')) {
      let j = i + (ch === '-' ? 1 : 0);
      while (j < source.length && /[0-9.]/.test(source[j]!)) j += 1;
      const raw = source.slice(i, j);
      const num = Number(raw);
      if (raw !== '-' && !Number.isNaN(num)) {
        push({ kind: 'number', value: num, line });
        i = j;
        continue;
      }
    }
    if (/[A-Za-z_]/.test(ch)) {
      let j = i + 1;
      while (j < source.length && /[A-Za-z0-9_/-]/.test(source[j]!)) j += 1;
      push({ kind: 'ident', value: source.slice(i, j), line });
      i = j;
      continue;
    }
    if ('{}[]=,.'.includes(ch)) {
      push({ kind: 'punct', value: ch, line });
      i += 1;
      continue;
    }
    // Interpolation / splat leftovers inside expressions — skip one char.
    i += 1;
  }

  return tokens;
}

function readString(source: string, start: number, line: number): { value: string; next: number; line: number } {
  const quote = source[start];
  let i = start + 1;
  let out = '';
  while (i < source.length) {
    const ch = source[i]!;
    if (ch === '\n') line += 1;
    if (ch === '\\' && i + 1 < source.length) {
      out += source[i + 1];
      i += 2;
      continue;
    }
    if (ch === quote) return { value: out, next: i + 1, line };
    out += ch;
    i += 1;
  }
  throw new HclParseError(`Unclosed string at line ${line}`);
}

function readHeredoc(source: string, start: number, line: number): { value: string; next: number; line: number } {
  let i = start + 2;
  const indent = source[i] === '-';
  if (indent) i += 1;
  const markerStart = i;
  while (i < source.length && /[A-Za-z0-9_]/.test(source[i]!)) i += 1;
  const marker = source.slice(markerStart, i);
  if (!marker) throw new HclParseError(`Malformed heredoc at line ${line}`);
  if (source[i] === '\n') {
    line += 1;
    i += 1;
  }
  const bodyStart = i;
  const re = new RegExp(`^${indent ? '[ \\t]*' : ''}${marker}\\s*$`, 'm');
  const rest = source.slice(bodyStart);
  const match = re.exec(rest);
  if (!match || match.index === undefined) throw new HclParseError(`Unclosed heredoc '${marker}' at line ${line}`);
  const body = rest.slice(0, match.index);
  line += body.split('\n').length;
  return { value: body.replace(/\n$/, ''), next: bodyStart + match.index + match[0].length, line };
}
