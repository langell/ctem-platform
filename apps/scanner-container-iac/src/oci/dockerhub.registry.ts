import { Inject, Injectable, Optional } from '@nestjs/common';
import type { DockerhubCredentials } from '../container.credential';
import type { DockerhubImageRef } from '../container.identity';
import {
  allowlistedDockerhubAuthUrl,
  allowlistedDockerhubBlobRedirect,
  allowlistedDockerhubRegistryUrl,
  dockerhubBlobUrl,
  dockerhubManifestUrl,
  dockerhubTokenUrl,
  ContainerEgressError,
} from '../container.egress';
import { DockerhubEgressError, isDockerhubRegistryHost } from '../dockerhub.egress';
import { EGRESS_DOCKERHUB_REGISTRY, registryPullFetch } from './pull-egress';
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
export const DOCKERHUB_FETCH = Symbol('DOCKERHUB_FETCH');

export interface DockerhubImagePuller {
  pull(
    ref: DockerhubImageRef,
    credentials: DockerhubCredentials,
    checkDeadline: () => boolean,
  ): Promise<ImagePull>;
}

/**
 * In-process OCI pull from allowlisted `registry-1.docker.io`.
 * Auth is HTTP Basic (`DOCKERHUB_USERNAME` + `DOCKERHUB_TOKEN`) on exact
 * `auth.docker.io` `/token`, then a registry bearer on
 * `registry-1.docker.io`. Token, manifest, and blob HTTP use
 * `@ctem/resilience` (`egress:dockerhub-registry`). No docker / podman /
 * skopeo / crane. No Hub listing host (`hub.docker.com`). No CDN follow. Layer blobs are cached
 * by digest for the life of the worker. Pull is by digest only.
 */
@Injectable()
export class DockerhubRegistry implements DockerhubImagePuller {
  private readonly layerCache = new Map<string, LayerSnapshot>();
  private readonly fetchImpl: typeof fetch;

  constructor(@Optional() @Inject(DOCKERHUB_FETCH) fetchImpl?: typeof fetch) {
    this.fetchImpl = fetchImpl ?? fetch;
  }

  async pull(
    ref: DockerhubImageRef,
    credentials: DockerhubCredentials,
    checkDeadline: () => boolean,
  ): Promise<ImagePull> {
    if (!checkDeadline()) {
      throw new ContainerPullError('Job deadline exceeded before Docker Hub pull');
    }

    const registryToken = await this.registryToken(ref, credentials, checkDeadline);
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
    ref: DockerhubImageRef,
    credentials: DockerhubCredentials,
    checkDeadline: () => boolean,
  ): Promise<string> {
    if (!checkDeadline()) {
      throw new ContainerPullError('Job deadline exceeded during Docker Hub token exchange');
    }
    const url = dockerhubTokenUrl(ref.namespace, ref.repository);
    // Belt: never send DOCKERHUB_* Basic off auth.docker.io.
    allowlistedDockerhubAuthUrl(url);
    const basic = Buffer.from(`${credentials.username}:${credentials.token}`, 'utf8').toString(
      'base64',
    );
    let res: Response;
    try {
      res = await registryPullFetch(
        EGRESS_DOCKERHUB_REGISTRY,
        url,
        {
          method: 'GET',
          headers: {
            'user-agent': 'ctem-platform',
            authorization: `Basic ${basic}`,
          },
          redirect: 'error',
        },
        this.fetchImpl,
      );
    } catch (err) {
      if (err instanceof DockerhubEgressError || err instanceof ContainerEgressError) throw err;
      throw new ContainerPullError(
        `Docker Hub token exchange failed: ${err instanceof Error ? err.message : String(err)} — refusing pull`,
      );
    }
    if (res.status === 401 || res.status === 403) {
      throw new ContainerPullError(
        `Docker Hub token exchange returned ${res.status} — refusing pull`,
      );
    }
    if (!res.ok) {
      throw new ContainerPullError(
        `Docker Hub token exchange returned ${res.status} — refusing pull`,
      );
    }
    let json: unknown;
    try {
      json = await res.json();
    } catch {
      throw new ContainerPullError('Docker Hub token exchange was not JSON — refusing pull');
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
      throw new ContainerPullError('Docker Hub token exchange returned no token — refusing pull');
    }
    return token.trim();
  }

  private async getManifest(
    ref: DockerhubImageRef,
    digest: string,
    registryToken: string,
    checkDeadline: () => boolean,
  ): Promise<unknown> {
    if (!checkDeadline())
      throw new ContainerPullError('Job deadline exceeded during manifest pull');
    const url = dockerhubManifestUrl(ref.namespace, ref.repository, digest);
    const res = await this.dockerhubGet(url, registryToken, MANIFEST_ACCEPT);
    if (res.status === 401 || res.status === 403) {
      throw new ContainerPullError(
        `Docker Hub manifest GET returned ${res.status} — refusing pull`,
      );
    }
    if (!res.ok) {
      throw new ContainerPullError(
        `Docker Hub manifest GET returned ${res.status} — refusing pull`,
      );
    }
    return res.json();
  }

  private async resolvePlatformManifest(
    ref: DockerhubImageRef,
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
          'Docker Hub index has no linux platform manifest — refusing incomplete inventory',
        );
      }
      const nested = await this.getManifest(ref, chosen.digest, registryToken, checkDeadline);
      return this.requireImageManifest(nested);
    }
    return this.requireImageManifest(json);
  }

  private requireImageManifest(json: unknown): OciManifest {
    if (!json || typeof json !== 'object') {
      throw new ContainerPullError(
        'Docker Hub manifest was not JSON — refusing incomplete inventory',
      );
    }
    const rec = json as OciManifest;
    if (!Array.isArray(rec.layers)) {
      throw new ContainerPullError(
        'Docker Hub image manifest missing layers — refusing incomplete inventory',
      );
    }
    return rec;
  }

  private async getBlob(
    ref: DockerhubImageRef,
    digest: string,
    registryToken: string,
    checkDeadline: () => boolean,
  ): Promise<Buffer> {
    if (!checkDeadline()) throw new ContainerPullError('Job deadline exceeded during blob pull');
    const url = dockerhubBlobUrl(ref.namespace, ref.repository, digest);
    const res = await this.dockerhubGet(url, registryToken, 'application/octet-stream', true);
    if (res.status === 401 || res.status === 403) {
      throw new ContainerPullError(`Docker Hub blob GET returned ${res.status} — refusing pull`);
    }
    if (!res.ok) {
      throw new ContainerPullError(`Docker Hub blob GET returned ${res.status} — refusing pull`);
    }
    return Buffer.from(await res.arrayBuffer());
  }

  /**
   * GET on `registry-1.docker.io` with the registry bearer. Blob redirects
   * stay on that exact host; never follow a CDN or tenant index.
   */
  private async dockerhubGet(
    url: string,
    registryToken: string,
    accept: string,
    followBlobRedirect = false,
  ): Promise<Response> {
    const dest = allowlistedDockerhubRegistryUrl(url);
    const headers: Record<string, string> = {
      accept,
      'user-agent': 'ctem-platform',
      authorization: `Bearer ${registryToken}`,
    };
    const res = await registryPullFetch(
      EGRESS_DOCKERHUB_REGISTRY,
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
      throw new ContainerPullError('Docker Hub blob redirect missing Location — refusing pull');
    }
    const next = allowlistedDockerhubBlobRedirect(new URL(location, dest).toString());
    const nextHeaders: Record<string, string> = { accept, 'user-agent': 'ctem-platform' };
    const nextHost = new URL(next).hostname;
    if (isDockerhubRegistryHost(nextHost)) {
      nextHeaders.authorization = `Bearer ${registryToken}`;
    }
    return registryPullFetch(
      EGRESS_DOCKERHUB_REGISTRY,
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
