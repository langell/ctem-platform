import { gunzipSync } from 'node:zlib';

export class LayerUnpackError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'LayerUnpackError';
  }
}

export const MAX_LAYER_BYTES = 256 * 1024 * 1024;
export const MAX_LAYER_FILES = 50_000;
export const MAX_INVENTORY_FILE_BYTES = 8 * 1024 * 1024;

export interface TarEntry {
  name: string;
  type: 'file' | 'dir' | 'symlink' | 'whiteout' | 'opaque';
  body?: Buffer;
  linkname?: string;
}

const GZIP_MAGIC = Buffer.from([0x1f, 0x8b]);
const ZSTD_MAGIC = Buffer.from([0x28, 0xb5, 0x2f, 0xfd]);

/**
 * Decompress an OCI layer blob in-process. Gzip and uncompressed tar only —
 * zstd/unknown compression throws (incomplete inventory, not a skip).
 */
export function decompressLayer(blob: Buffer, mediaType?: string): Buffer {
  const type = (mediaType ?? '').toLowerCase();
  if (type.includes('zstd') || blob.subarray(0, 4).equals(ZSTD_MAGIC)) {
    throw new LayerUnpackError(
      'Layer uses zstd compression — refusing incomplete in-process unpack (no CLI fallback)',
    );
  }
  if (type.includes('gzip') || blob.subarray(0, 2).equals(GZIP_MAGIC)) {
    try {
      const out = gunzipSync(blob);
      if (out.length > MAX_LAYER_BYTES) {
        throw new LayerUnpackError(
          `Uncompressed layer ${out.length} bytes exceeds cap ${MAX_LAYER_BYTES} — refusing incomplete inventory`,
        );
      }
      return out;
    } catch (err) {
      if (err instanceof LayerUnpackError) throw err;
      throw new LayerUnpackError(
        `Failed to gunzip layer: ${err instanceof Error ? err.message : String(err)} — refusing incomplete inventory`,
      );
    }
  }
  if (blob.length > MAX_LAYER_BYTES) {
    throw new LayerUnpackError(
      `Layer ${blob.length} bytes exceeds cap ${MAX_LAYER_BYTES} — refusing incomplete inventory`,
    );
  }
  return blob;
}

/**
 * Walk a ustar/posix tar in-process. Corrupt headers, truncated payloads, or
 * a file cap throw — a partial walk must not look like success.
 */
export function parseTar(buf: Buffer): TarEntry[] {
  const entries: TarEntry[] = [];
  let offset = 0;
  let pendingPax: Record<string, string> = {};
  let pendingLongName: string | undefined;

  while (offset + 512 <= buf.length) {
    const header = buf.subarray(offset, offset + 512);
    if (isZeroBlock(header)) {
      // End of archive: two zero blocks, or one at EOF.
      break;
    }
    if (!validChecksum(header)) {
      throw new LayerUnpackError('Corrupt tar header checksum — refusing incomplete layer inventory');
    }

    const typeflag = String.fromCharCode(header[156] ?? 0);
    const size = parseOctal(header.subarray(124, 136));
    const rawName = readCString(header.subarray(0, 100));
    const prefix = readCString(header.subarray(345, 500));
    const linkname = readCString(header.subarray(157, 257));
    let name = pendingLongName ?? pendingPax.path ?? (prefix ? `${prefix}/${rawName}` : rawName);
    pendingLongName = undefined;
    const pax = pendingPax;
    pendingPax = {};

    offset += 512;
    const padded = Math.ceil(size / 512) * 512;
    if (offset + size > buf.length) {
      throw new LayerUnpackError(`Truncated tar payload for '${name}' — refusing incomplete layer inventory`);
    }
    const body = buf.subarray(offset, offset + size);
    offset += padded;

    if (entries.length >= MAX_LAYER_FILES) {
      throw new LayerUnpackError(
        `Layer tar exceeded ${MAX_LAYER_FILES} files — refusing truncated inventory`,
      );
    }

    if (typeflag === 'x' || typeflag === 'g') {
      pendingPax = { ...pax, ...parsePax(body) };
      continue;
    }
    if (typeflag === 'L') {
      pendingLongName = readCString(body);
      continue;
    }
    if (typeflag === 'K') {
      continue;
    }

    name = name.replace(/^\.\//, '').replace(/\/+$/, '');
    if (!name) continue;

    const base = basename(name);
    if (base === '.wh..wh..opq') {
      entries.push({ name: dirname(name), type: 'opaque' });
      continue;
    }
    if (base.startsWith('.wh.')) {
      const target = joinDir(dirname(name), base.slice(4));
      entries.push({ name: target, type: 'whiteout' });
      continue;
    }

    if (typeflag === '5' || name.endsWith('/')) {
      entries.push({ name: name.replace(/\/+$/, ''), type: 'dir' });
      continue;
    }
    if (typeflag === '2' || typeflag === '1') {
      entries.push({ name, type: 'symlink', linkname: pax.linkpath ?? linkname });
      continue;
    }
    if (typeflag === '0' || typeflag === '\0' || typeflag === '') {
      if (body.length > MAX_INVENTORY_FILE_BYTES && isInventoryPath(name)) {
        throw new LayerUnpackError(
          `Inventory file '${name}' is ${body.length} bytes over cap — refusing incomplete layer inventory`,
        );
      }
      entries.push({ name, type: 'file', body: Buffer.from(body) });
      continue;
    }
    // Other types (fifo, device) are not inventory — skip, do not fail.
  }

  return entries;
}

export function isInventoryPath(path: string): boolean {
  const p = path.replace(/^\//, '');
  if (p === 'lib/apk/db/installed' || p.endsWith('/lib/apk/db/installed')) return true;
  if (p === 'var/lib/dpkg/status' || p.endsWith('/var/lib/dpkg/status')) return true;
  if (p.includes('var/lib/dpkg/status.d/')) return true;
  if (p.includes('var/lib/rpm/') || p.includes('usr/lib/sysimage/rpm/')) return true;
  if (p.endsWith('/package.json') && p.includes('node_modules/')) return true;
  if (p.endsWith('.dist-info/METADATA') || p.endsWith('.egg-info/PKG-INFO')) return true;
  if (p.includes('/specifications/') && p.endsWith('.gemspec')) return true;
  if (p === 'etc/os-release' || p.endsWith('/etc/os-release')) return true;
  return false;
}

function isZeroBlock(block: Buffer): boolean {
  for (const b of block) if (b !== 0) return false;
  return true;
}

function validChecksum(header: Buffer): boolean {
  const recorded = parseOctal(header.subarray(148, 156));
  let sum = 0;
  for (let i = 0; i < 512; i++) {
    sum += i >= 148 && i < 156 ? 0x20 : (header[i] ?? 0);
  }
  return sum === recorded;
}

function parseOctal(buf: Buffer): number {
  const text = readCString(buf).replace(/^[0\s]*/, '').trim();
  if (!text) return 0;
  const n = Number.parseInt(text, 8);
  if (!Number.isFinite(n) || n < 0) {
    throw new LayerUnpackError('Invalid tar size field — refusing incomplete layer inventory');
  }
  return n;
}

function readCString(buf: Buffer): string {
  const end = buf.indexOf(0);
  return buf.subarray(0, end === -1 ? buf.length : end).toString('utf8').trim();
}

function parsePax(body: Buffer): Record<string, string> {
  const text = body.toString('utf8');
  const out: Record<string, string> = {};
  let i = 0;
  while (i < text.length) {
    const sp = text.indexOf(' ', i);
    if (sp < 0) break;
    const len = Number(text.slice(i, sp));
    if (!Number.isFinite(len) || len <= 0) break;
    const rec = text.slice(i, i + len);
    const inner = rec.slice(sp - i + 1).replace(/\n$/, '');
    const split = inner.indexOf('=');
    if (split > 0) out[inner.slice(0, split)] = inner.slice(split + 1);
    i += len;
  }
  return out;
}

function basename(path: string): string {
  const i = path.lastIndexOf('/');
  return i === -1 ? path : path.slice(i + 1);
}

function dirname(path: string): string {
  const i = path.lastIndexOf('/');
  return i === -1 ? '' : path.slice(0, i);
}

function joinDir(dir: string, name: string): string {
  return dir ? `${dir}/${name}` : name;
}
