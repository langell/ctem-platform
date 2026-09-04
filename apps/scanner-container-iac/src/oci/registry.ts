import { Injectable } from '@nestjs/common';
import type { GhcrImageRef } from '../container.identity';
import {
  allowlistedGhcrBlobRedirect,
  allowlistedGhcrUrl,
  ghcrBlobUrl,
  ghcrManifestUrl,
  ghcrTokenUrl,
  isGhcrRegistryHost,
  ContainerEgressError,
} from '../container.egress';
import {
  decompressLayer,
  isInventoryPath,
  parseTar,
  LayerUnpackError,
  type TarEntry,
} from './tar';

export class ContainerPullError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ContainerPullError';
  }
}

export const MAX_IMAGE_LAYERS = 128;

const MANIFEST_ACCEPT = [
  'application/vnd.oci.image.index.v1+json',
  'application/vnd.docker.distribution.manifest.list.v2+json',
  'application/vnd.oci.image.manifest.v1+json',
  'application/vnd.docker.distribution.manifest.v2+json',
  'application/vnd.oci.image.manifest.v1+json',
].join(', ');

export interface LayerSnapshot {
  digest: string;
  mediaType: string;
  files: Map<string, Buffer>;
  whiteouts: string[];
  opaqueDirs: string[];
}

export interface ImagePull {
  digest: string;
  owner: string;
  name: string;
  layers: LayerSnapshot[];
}

export interface ImagePuller {
  pull(
    ref: GhcrImageRef,
    token: string | undefined,
    checkDeadline: () => boolean,
  ): Promise<ImagePull>;
}

interface OciIndex {
  mediaType?: string;
  manifests?: Array<{
    digest?: string;
    mediaType?: string;
    platform?: { os?: string; architecture?: string; variant?: string };
  }>;
}

interface OciManifest {
  mediaType?: string;
  layers?: Array<{ digest?: string; mediaType?: string; size?: number }>;
  config?: { digest?: string; mediaType?: string };
}

/**
 * In-process OCI pull from allowlisted ghcr.io. No docker/podman/skopeo/crane.
 * Layer blobs are cached by digest for the life of the worker.
 */
@Injectable()
export class GhcrRegistry implements ImagePuller {
  private readonly layerCache = new Map<string, LayerSnapshot>();

  constructor(private readonly fetchImpl: typeof fetch = fetch) {}

  async pull(
    ref: GhcrImageRef,
    token: string | undefined,
    checkDeadline: () => boolean,
  ): Promise<ImagePull> {
    if (!checkDeadline()) {
      throw new ContainerPullError('Job deadline exceeded before GHCR pull');
    }

    const registryToken = await this.registryToken(ref, token);
    const manifestJson = await this.getManifest(ref, ref.digest, registryToken, checkDeadline);
    const platform = await this.resolvePlatformManifest(ref, manifestJson, registryToken, checkDeadline);
    const layers = platform.layers ?? [];
    if (layers.length > MAX_IMAGE_LAYERS) {
      throw new ContainerPullError(
        `Image has ${layers.length} layers (cap ${MAX_IMAGE_LAYERS}) — refusing incomplete inventory`,
      );
    }

    const snapshots: LayerSnapshot[] = [];
    for (const layer of layers) {
      if (!checkDeadline()) {
        throw new ContainerPullError('Job deadline exceeded mid-pull — refusing incomplete inventory');
      }
      const digest = layer.digest;
      const mediaType = layer.mediaType ?? '';
      if (!digest || !/^sha256:[a-f0-9]{64}$/i.test(digest)) {
        throw new ContainerPullError('Layer descriptor missing sha256 digest — refusing incomplete inventory');
      }
      const cached = this.layerCache.get(digest.toLowerCase());
      if (cached) {
        snapshots.push(cached);
        continue;
      }
      const blob = await this.getBlob(ref, digest, registryToken, checkDeadline);
      const snapshot = unpackLayer(digest.toLowerCase(), mediaType, blob);
      this.layerCache.set(snapshot.digest, snapshot);
      snapshots.push(snapshot);
    }

    return { digest: ref.digest, owner: ref.owner, name: ref.name, layers: snapshots };
  }

  private async registryToken(ref: GhcrImageRef, githubToken: string | undefined): Promise<string | undefined> {
    const url = ghcrTokenUrl(ref.owner, ref.name);
    const headers: Record<string, string> = { 'user-agent': 'ctem-platform' };
    if (githubToken) headers.authorization = `Bearer ${githubToken}`;
    const res = await this.fetchImpl(url, { method: 'GET', headers, signal: AbortSignal.timeout(20_000) });
    if (res.status === 404 || res.status === 401 || res.status === 403) {
      if (!githubToken) {
        throw new ContainerPullError(
          `GHCR token exchange returned ${res.status} without credentials — refusing unauthenticated pull`,
        );
      }
      throw new ContainerPullError(`GHCR token exchange returned ${res.status} — refusing pull`);
    }
    if (!res.ok) {
      throw new ContainerPullError(`GHCR token exchange returned ${res.status} — refusing pull`);
    }
    const body = (await res.json()) as { token?: unknown; access_token?: unknown };
    const token = typeof body.token === 'string' ? body.token : typeof body.access_token === 'string' ? body.access_token : undefined;
    if (!token || !token.trim()) {
      throw new ContainerPullError('GHCR token exchange returned no token — refusing pull');
    }
    return token.trim();
  }

  private async getManifest(
    ref: GhcrImageRef,
    digest: string,
    registryToken: string | undefined,
    checkDeadline: () => boolean,
  ): Promise<unknown> {
    if (!checkDeadline()) throw new ContainerPullError('Job deadline exceeded during manifest pull');
    const url = ghcrManifestUrl(ref.owner, ref.name, digest);
    const res = await this.ghcrGet(url, registryToken, MANIFEST_ACCEPT);
    if (res.status === 401 || res.status === 403) {
      throw new ContainerPullError(`GHCR manifest GET returned ${res.status} — refusing pull`);
    }
    if (!res.ok) {
      throw new ContainerPullError(`GHCR manifest GET returned ${res.status} — refusing pull`);
    }
    return res.json();
  }

  private async resolvePlatformManifest(
    ref: GhcrImageRef,
    json: unknown,
    registryToken: string | undefined,
    checkDeadline: () => boolean,
  ): Promise<OciManifest> {
    const rec = json && typeof json === 'object' ? (json as OciIndex & OciManifest) : {};
    const mediaType = rec.mediaType ?? '';
    const isIndex =
      mediaType.includes('image.index') ||
      mediaType.includes('manifest.list') ||
      Array.isArray(rec.manifests);

    if (isIndex && rec.manifests?.length) {
      const chosen = pickPlatform(rec.manifests);
      if (!chosen?.digest) {
        throw new ContainerPullError('GHCR index has no linux platform manifest — refusing incomplete inventory');
      }
      const nested = await this.getManifest(ref, chosen.digest, registryToken, checkDeadline);
      return this.requireImageManifest(nested);
    }
    return this.requireImageManifest(json);
  }

  private requireImageManifest(json: unknown): OciManifest {
    if (!json || typeof json !== 'object') {
      throw new ContainerPullError('GHCR manifest was not JSON — refusing incomplete inventory');
    }
    const rec = json as OciManifest;
    if (!Array.isArray(rec.layers)) {
      throw new ContainerPullError('GHCR image manifest missing layers — refusing incomplete inventory');
    }
    return rec;
  }

  private async getBlob(
    ref: GhcrImageRef,
    digest: string,
    registryToken: string | undefined,
    checkDeadline: () => boolean,
  ): Promise<Buffer> {
    if (!checkDeadline()) throw new ContainerPullError('Job deadline exceeded during blob pull');
    const url = ghcrBlobUrl(ref.owner, ref.name, digest);
    const res = await this.ghcrGet(url, registryToken, 'application/octet-stream', true);
    if (res.status === 401 || res.status === 403) {
      throw new ContainerPullError(`GHCR blob GET returned ${res.status} — refusing pull`);
    }
    if (!res.ok) {
      throw new ContainerPullError(`GHCR blob GET returned ${res.status} — refusing pull`);
    }
    const buf = Buffer.from(await res.arrayBuffer());
    return buf;
  }

  /**
   * GET on ghcr.io with optional registry bearer. Blob redirects to the GitHub
   * CDN are followed without the bearer (pre-signed Location).
   */
  private async ghcrGet(
    url: string,
    registryToken: string | undefined,
    accept: string,
    followBlobRedirect = false,
  ): Promise<Response> {
    const dest = allowlistedGhcrUrl(url);
    const headers: Record<string, string> = {
      accept,
      'user-agent': 'ctem-platform',
    };
    if (registryToken) headers.authorization = `Bearer ${registryToken}`;
    const res = await this.fetchImpl(dest, {
      method: 'GET',
      headers,
      redirect: followBlobRedirect ? 'manual' : 'error',
      signal: AbortSignal.timeout(60_000),
    });

    if (!followBlobRedirect) return res;
    if (res.status < 300 || res.status >= 400) return res;

    const location = res.headers.get('location');
    if (!location) {
      throw new ContainerPullError('GHCR blob redirect missing Location — refusing pull');
    }
    const next = allowlistedGhcrBlobRedirect(new URL(location, dest).toString());
    const nextHeaders: Record<string, string> = { accept, 'user-agent': 'ctem-platform' };
    // Cross-origin CDN: never attach the registry bearer (pre-signed URL).
    const nextHost = new URL(next).hostname;
    if (isGhcrRegistryHost(nextHost) && registryToken) {
      nextHeaders.authorization = `Bearer ${registryToken}`;
    }
    return this.fetchImpl(next, {
      method: 'GET',
      headers: nextHeaders,
      redirect: 'error',
      signal: AbortSignal.timeout(60_000),
    });
  }
}

function pickPlatform(
  manifests: NonNullable<OciIndex['manifests']>,
): NonNullable<OciIndex['manifests']>[number] | undefined {
  const linux = manifests.filter((m) => (m.platform?.os ?? 'linux') === 'linux');
  return (
    linux.find((m) => m.platform?.architecture === 'amd64') ??
    linux.find((m) => m.platform?.architecture === 'arm64') ??
    linux[0] ??
    manifests[0]
  );
}

function unpackLayer(digest: string, mediaType: string, blob: Buffer): LayerSnapshot {
  let entries: TarEntry[];
  try {
    const tar = decompressLayer(blob, mediaType);
    entries = parseTar(tar);
  } catch (err) {
    if (err instanceof LayerUnpackError || err instanceof ContainerEgressError) throw err;
    throw new ContainerPullError(
      `Failed to unpack layer ${digest}: ${err instanceof Error ? err.message : String(err)} — refusing incomplete inventory`,
    );
  }

  const files = new Map<string, Buffer>();
  const whiteouts: string[] = [];
  const opaqueDirs: string[] = [];
  for (const entry of entries) {
    if (entry.type === 'whiteout') {
      whiteouts.push(entry.name);
      continue;
    }
    if (entry.type === 'opaque') {
      opaqueDirs.push(entry.name);
      continue;
    }
    if (entry.type === 'file' && entry.body && isInventoryPath(entry.name)) {
      files.set(normalizePath(entry.name), entry.body);
    }
  }
  return { digest, mediaType, files, whiteouts, opaqueDirs };
}

function normalizePath(path: string): string {
  return path.replace(/^\//, '').replace(/^\.\//, '');
}

export { ContainerEgressError };
