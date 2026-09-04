import type { LayerSnapshot } from '../oci/registry';

export class ContainerInventoryError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ContainerInventoryError';
  }
}

export const MAX_INVENTORY_PACKAGES = 20_000;

export interface ImagePackage {
  name: string;
  version: string;
  ecosystem: string;
  purl: string;
  path: string;
  layerDigest: string;
  origin: 'os' | 'app';
}

interface OverlayFile {
  content: Buffer;
  layerDigest: string;
}

/**
 * Apply layers oldest-first (whiteouts + last-write-wins) and inventory OS +
 * app packages. Introducer is the layer that first wrote the package at its
 * current version (an OS DB rewrite that does not change a package keeps the
 * earlier layer). A truncated walk or an unparseable package DB throws.
 */
export function inventoryImage(layers: LayerSnapshot[]): ImagePackage[] {
  const overlay = new Map<string, OverlayFile>();
  const osByName = new Map<string, ImagePackage>();

  for (const layer of layers) {
    applyLayer(overlay, layer);
    const osFiles = osDbFiles(overlay);
    const dbTouched = [...osFiles.values()].some((file) => file.layerDigest === layer.digest);
    if (!dbTouched) continue;

    const parsed = parseOsPackages(
      new Map([...osFiles.entries()].map(([path, file]) => [path, file.content])),
      layer.digest,
    );
    const next = new Map<string, ImagePackage>();
    for (const pkg of parsed) {
      const key = `os:${pkg.ecosystem}:${pkg.name}`;
      const prev = osByName.get(key);
      if (prev && prev.version === pkg.version) next.set(key, prev);
      else next.set(key, { ...pkg, layerDigest: layer.digest });
    }
    osByName.clear();
    for (const [key, pkg] of next) osByName.set(key, pkg);
  }

  assertNoUnparsedRpm(overlay);
  const app = parseAppPackages(overlay);
  const all = [...osByName.values(), ...app];
  if (all.length > MAX_INVENTORY_PACKAGES) {
    throw new ContainerInventoryError(
      `Package inventory exceeded ${MAX_INVENTORY_PACKAGES} — refusing truncated inventory`,
    );
  }
  return all;
}

function applyLayer(overlay: Map<string, OverlayFile>, layer: LayerSnapshot): void {
  for (const dir of layer.opaqueDirs) {
    const prefix = dir ? `${dir}/` : '';
    for (const path of [...overlay.keys()]) {
      if (path === dir || path.startsWith(prefix)) overlay.delete(path);
    }
  }
  for (const path of layer.whiteouts) {
    overlay.delete(path);
    const prefix = `${path}/`;
    for (const existing of [...overlay.keys()]) {
      if (existing.startsWith(prefix)) overlay.delete(existing);
    }
  }
  for (const [path, content] of layer.files) {
    overlay.set(path, { content, layerDigest: layer.digest });
  }
}

function osDbFiles(overlay: Map<string, OverlayFile>): Map<string, OverlayFile> {
  const out = new Map<string, OverlayFile>();
  for (const [path, file] of overlay) {
    if (isOsDbPath(path)) out.set(path, file);
  }
  return out;
}

function assertNoUnparsedRpm(overlay: Map<string, OverlayFile>): void {
  for (const path of overlay.keys()) {
    if (
      path.includes('var/lib/rpm/') ||
      path.includes('usr/lib/sysimage/rpm/') ||
      /(^|\/)Packages(\.db)?$/.test(path)
    ) {
      if (path.endsWith('rpmdb.sqlite') || path.endsWith('Packages') || path.endsWith('Packages.db')) {
        throw new ContainerInventoryError(
          `RPM database at '${path}' cannot be inventoried in-process — refusing incomplete layer inventory`,
        );
      }
    }
  }
}

function isOsDbPath(path: string): boolean {
  return (
    path.endsWith('lib/apk/db/installed') ||
    path.endsWith('var/lib/dpkg/status') ||
    path.includes('var/lib/dpkg/status.d/')
  );
}

function parseOsPackages(files: Map<string, Buffer>, layerDigest: string): ImagePackage[] {
  const out: ImagePackage[] = [];
  for (const [path, body] of files) {
    if (path.endsWith('lib/apk/db/installed')) {
      out.push(...parseApkInstalled(body.toString('utf8'), path, layerDigest));
    } else if (path.endsWith('var/lib/dpkg/status') || path.includes('var/lib/dpkg/status.d/')) {
      out.push(...parseDpkgStatus(body.toString('utf8'), path, layerDigest));
    }
  }
  return out;
}

function parseAppPackages(overlay: Map<string, OverlayFile>): ImagePackage[] {
  const out: ImagePackage[] = [];
  for (const [path, file] of overlay) {
    if (path.endsWith('/package.json') && path.includes('node_modules/')) {
      const pkg = parseNpmPackageJson(file.content.toString('utf8'), path, file.layerDigest);
      if (pkg) out.push(pkg);
      continue;
    }
    if (path.endsWith('.dist-info/METADATA') || path.endsWith('.egg-info/PKG-INFO')) {
      const pkg = parsePythonMetadata(file.content.toString('utf8'), path, file.layerDigest);
      if (pkg) out.push(pkg);
      continue;
    }
    if (path.includes('/specifications/') && path.endsWith('.gemspec')) {
      const pkg = parseGemspec(file.content.toString('utf8'), path, file.layerDigest);
      if (pkg) out.push(pkg);
    }
  }
  return out;
}

export function parseApkInstalled(content: string, path: string, layerDigest: string): ImagePackage[] {
  const out: ImagePackage[] = [];
  let name = '';
  let version = '';
  const finish = (): void => {
    if (name && version) {
      out.push({
        name,
        version,
        ecosystem: 'Alpine',
        purl: `pkg:apk/${encodePurl(name)}@${version}?distro=alpine`,
        path,
        layerDigest,
        origin: 'os',
      });
    }
    name = '';
    version = '';
  };
  for (const line of content.split('\n')) {
    if (line === '') {
      finish();
      continue;
    }
    if (line.startsWith('P:')) name = line.slice(2).trim();
    else if (line.startsWith('V:')) version = line.slice(2).trim();
  }
  finish();
  return out;
}

export function parseDpkgStatus(content: string, path: string, layerDigest: string): ImagePackage[] {
  const out: ImagePackage[] = [];
  let name = '';
  let version = '';
  let status = '';
  const finish = (): void => {
    if (name && version && status.includes('installed') && !status.includes('not-installed')) {
      out.push({
        name,
        version,
        ecosystem: 'Debian',
        purl: `pkg:deb/debian/${encodePurl(name)}@${version}`,
        path,
        layerDigest,
        origin: 'os',
      });
    }
    name = '';
    version = '';
    status = '';
  };
  for (const line of content.split('\n')) {
    if (line === '') {
      finish();
      continue;
    }
    if (line.startsWith('Package:')) name = line.slice('Package:'.length).trim();
    else if (line.startsWith('Version:')) version = line.slice('Version:'.length).trim();
    else if (line.startsWith('Status:')) status = line.slice('Status:'.length).trim();
  }
  finish();
  return out;
}

function parseNpmPackageJson(content: string, path: string, layerDigest: string): ImagePackage | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    throw new ContainerInventoryError(
      `Failed to parse '${path}' as JSON — refusing incomplete layer inventory`,
    );
  }
  if (!parsed || typeof parsed !== 'object') return undefined;
  const rec = parsed as { name?: unknown; version?: unknown };
  if (typeof rec.name !== 'string' || !rec.name || typeof rec.version !== 'string' || !rec.version) {
    return undefined;
  }
  return {
    name: rec.name,
    version: rec.version,
    ecosystem: 'npm',
    purl: npmPurl(rec.name, rec.version),
    path,
    layerDigest,
    origin: 'app',
  };
}

function parsePythonMetadata(content: string, path: string, layerDigest: string): ImagePackage | undefined {
  let name = '';
  let version = '';
  for (const line of content.split('\n')) {
    if (line.startsWith('Name:')) name = line.slice(5).trim();
    else if (line.startsWith('Version:')) version = line.slice(8).trim();
  }
  if (!name || !version) return undefined;
  return {
    name,
    version,
    ecosystem: 'PyPI',
    purl: `pkg:pypi/${encodePurl(name)}@${version}`,
    path,
    layerDigest,
    origin: 'app',
  };
}

function parseGemspec(content: string, path: string, layerDigest: string): ImagePackage | undefined {
  const name = content.match(/\.name\s*=\s*["']([^"']+)["']/)?.[1];
  const version = content.match(/\.version\s*=\s*["']([^"']+)["']/)?.[1];
  if (!name || !version) return undefined;
  return {
    name,
    version,
    ecosystem: 'RubyGems',
    purl: `pkg:gem/${encodePurl(name)}@${version}`,
    path,
    layerDigest,
    origin: 'app',
  };
}

function npmPurl(name: string, version: string): string {
  if (name.startsWith('@')) {
    const slash = name.indexOf('/');
    if (slash > 1) {
      const ns = name.slice(1, slash);
      const pkg = name.slice(slash + 1);
      return `pkg:npm/%40${encodePurl(ns)}/${encodePurl(pkg)}@${version}`;
    }
  }
  return `pkg:npm/${encodePurl(name)}@${version}`;
}

function encodePurl(value: string): string {
  return encodeURIComponent(value).replace(/%2F/g, '/');
}
