import { Inject, Injectable, Optional } from '@nestjs/common';
import type { QuayImageRef } from '../container.identity';
import {
  allowlistedQuayAuthUrl,
  allowlistedQuayBlobRedirect,
  allowlistedQuayRegistryUrl,
  quayBlobUrl,
  quayManifestUrl,
  quayTokenUrl,
  ContainerEgressError,
} from '../container.egress';
import { QuayEgressError, isQuayRegistryHost } from '../quay.egress';
import { EGRESS_QUAY_REGISTRY, registryPullFetch } from './pull-egress';
import {
  ContainerPullError,
  MAX_IMAGE_LAYERS,
  MANIFEST_ACCEPT,
  pickPlatform,
  unpackLayer,
  type ImagePull,
  type LayerSnapshot,
  type OciIndex,
  type OciManifest,
} from './registry';

/** Injection token for overriding the fetch implementation (tests, egress shims). */
export const QUAY_FETCH = Symbol('QUAY_FETCH');

export interface QuayImagePuller {
  pull(ref: QuayImageRef, token: string, checkDeadline: () => boolean): Promise<ImagePull>;
}

/**
 * In-process OCI pull from allowlisted `quay.io`. Auth is Bearer
 * (`env:QUAY_*`) on exact `quay.io` `/v2/auth`, then a registry bearer
 * on `quay.io` `/v2/` manifests + blobs. Token, manifest, and blob HTTP
 * use `@ctem/resilience` (`egress:quay-registry`). No docker / podman / skopeo /
 * crane. No inventory REST (`/api/v1/`). No CDN follow. No self-hosted
 * Quay host. Layer blobs are cached by digest for the life of the
 * worker. Pull is by digest only.
 */
@Injectable()
export class QuayRegistry implements QuayImagePuller {
  private readonly layerCache = new Map<string, LayerSnapshot>();
  private readonly fetchImpl: typeof fetch;

  constructor(@Optional() @Inject(QUAY_FETCH) fetchImpl?: typeof fetch) {
    this.fetchImpl = fetchImpl ?? fetch;
  }

  async pull(ref: QuayImageRef, token: string, checkDeadline: () => boolean): Promise<ImagePull> {
    if (!checkDeadline()) {
      throw new ContainerPullError('Job deadline exceeded before Quay pull');
    }

    const registryToken = await this.registryToken(ref, token, checkDeadline);
    const manifestJson = await this.getManifest(ref, ref.digest, registryToken, checkDeadline);
    const platform = await this.resolvePlatformManifest(
      ref,
      manifestJson,
      registryToken,
      checkDeadline,
    );
    const layers = platform.layers ?? [];
    if (layers.length > MAX_IMAGE_LAYERS) {
      throw new ContainerPullError(
        `Image has ${layers.length} layers (cap ${MAX_IMAGE_LAYERS}) — refusing incomplete inventory`,
      );
    }

    const snapshots: LayerSnapshot[] = [];
    for (const layer of layers) {
      if (!checkDeadline()) {
        throw new ContainerPullError(
          'Job deadline exceeded mid-pull — refusing incomplete inventory',
        );
      }
      const digest = layer.digest;
      const mediaType = layer.mediaType ?? '';
      if (!digest || !/^sha256:[a-f0-9]{64}$/i.test(digest)) {
        throw new ContainerPullError(
          'Layer descriptor missing sha256 digest — refusing incomplete inventory',
        );
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

    return {
      digest: ref.digest,
      owner: ref.namespace,
      name: ref.repository,
      layers: snapshots,
    };
  }

  private async registryToken(
    ref: QuayImageRef,
    quayToken: string,
    checkDeadline: () => boolean,
  ): Promise<string> {
    if (!checkDeadline()) {
      throw new ContainerPullError('Job deadline exceeded during Quay token exchange');
    }
    const url = quayTokenUrl(ref.namespace, ref.repository);
    // Belt: never send QUAY_* Bearer off quay.io /v2/auth.
    allowlistedQuayAuthUrl(url);
    let res: Response;
    try {
      res = await registryPullFetch(
        EGRESS_QUAY_REGISTRY,
        url,
        {
          method: 'GET',
          headers: {
            'user-agent': 'ctem-platform',
            authorization: `Bearer ${quayToken}`,
          },
          redirect: 'error',
        },
        this.fetchImpl,
      );
    } catch (err) {
      if (err instanceof QuayEgressError || err instanceof ContainerEgressError) throw err;
      throw new ContainerPullError(
        `Quay token exchange failed: ${err instanceof Error ? err.message : String(err)} — refusing pull`,
      );
    }
    if (res.status === 401 || res.status === 403) {
      throw new ContainerPullError(`Quay token exchange returned ${res.status} — refusing pull`);
    }
    if (!res.ok) {
      throw new ContainerPullError(`Quay token exchange returned ${res.status} — refusing pull`);
    }
    let json: unknown;
    try {
      json = await res.json();
    } catch {
      throw new ContainerPullError('Quay token exchange was not JSON — refusing pull');
    }
    const rec =
      json && typeof json === 'object' ? (json as { token?: unknown; access_token?: unknown }) : {};
    const token =
      typeof rec.token === 'string'
        ? rec.token
        : typeof rec.access_token === 'string'
          ? rec.access_token
          : undefined;
    if (!token || !token.trim()) {
      throw new ContainerPullError('Quay token exchange returned no token — refusing pull');
    }
    return token.trim();
  }

  private async getManifest(
    ref: QuayImageRef,
    digest: string,
    registryToken: string,
    checkDeadline: () => boolean,
  ): Promise<unknown> {
    if (!checkDeadline())
      throw new ContainerPullError('Job deadline exceeded during manifest pull');
    const url = quayManifestUrl(ref.namespace, ref.repository, digest);
    const res = await this.quayGet(url, registryToken, MANIFEST_ACCEPT);
    if (res.status === 401 || res.status === 403) {
      throw new ContainerPullError(`Quay manifest GET returned ${res.status} — refusing pull`);
    }
    if (!res.ok) {
      throw new ContainerPullError(`Quay manifest GET returned ${res.status} — refusing pull`);
    }
    return res.json();
  }

  private async resolvePlatformManifest(
    ref: QuayImageRef,
    json: unknown,
    registryToken: string,
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
        throw new ContainerPullError(
          'Quay index has no linux platform manifest — refusing incomplete inventory',
        );
      }
      const nested = await this.getManifest(ref, chosen.digest, registryToken, checkDeadline);
      return this.requireImageManifest(nested);
    }
    return this.requireImageManifest(json);
  }

  private requireImageManifest(json: unknown): OciManifest {
    if (!json || typeof json !== 'object') {
      throw new ContainerPullError('Quay manifest was not JSON — refusing incomplete inventory');
    }
    const rec = json as OciManifest;
    if (!Array.isArray(rec.layers)) {
      throw new ContainerPullError(
        'Quay image manifest missing layers — refusing incomplete inventory',
      );
    }
    return rec;
  }

  private async getBlob(
    ref: QuayImageRef,
    digest: string,
    registryToken: string,
    checkDeadline: () => boolean,
  ): Promise<Buffer> {
    if (!checkDeadline()) throw new ContainerPullError('Job deadline exceeded during blob pull');
    const url = quayBlobUrl(ref.namespace, ref.repository, digest);
    const res = await this.quayGet(url, registryToken, 'application/octet-stream', true);
    if (res.status === 401 || res.status === 403) {
      throw new ContainerPullError(`Quay blob GET returned ${res.status} — refusing pull`);
    }
    if (!res.ok) {
      throw new ContainerPullError(`Quay blob GET returned ${res.status} — refusing pull`);
    }
    return Buffer.from(await res.arrayBuffer());
  }

  /**
   * GET on `quay.io` with the registry bearer. Blob redirects stay on
   * that exact host; never follow a CDN or self-hosted Quay.
   */
  private async quayGet(
    url: string,
    registryToken: string,
    accept: string,
    followBlobRedirect = false,
  ): Promise<Response> {
    const dest = allowlistedQuayRegistryUrl(url);
    const headers: Record<string, string> = {
      accept,
      'user-agent': 'ctem-platform',
      authorization: `Bearer ${registryToken}`,
    };
    const res = await registryPullFetch(
      EGRESS_QUAY_REGISTRY,
      dest,
      {
        method: 'GET',
        headers,
        redirect: followBlobRedirect ? 'manual' : 'error',
      },
      this.fetchImpl,
    );

    if (!followBlobRedirect) return res;
    if (res.status < 300 || res.status >= 400) return res;

    const location = res.headers.get('location');
    if (!location) {
      throw new ContainerPullError('Quay blob redirect missing Location — refusing pull');
    }
    const next = allowlistedQuayBlobRedirect(new URL(location, dest).toString());
    const nextHeaders: Record<string, string> = { accept, 'user-agent': 'ctem-platform' };
    const nextHost = new URL(next).hostname;
    if (isQuayRegistryHost(nextHost)) {
      nextHeaders.authorization = `Bearer ${registryToken}`;
    }
    return registryPullFetch(
      EGRESS_QUAY_REGISTRY,
      next,
      {
        method: 'GET',
        headers: nextHeaders,
        redirect: 'error',
      },
      this.fetchImpl,
    );
  }
}

export { ContainerEgressError, ContainerPullError };
