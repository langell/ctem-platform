import { Inject, Injectable, Optional } from '@nestjs/common';
import type { GcpCredentials } from '../container.credential';
import type { GcrImageRef } from '../container.identity';
import {
  allowlistedGcrBlobRedirect,
  allowlistedGcrRegistryUrl,
  gcrBlobUrl,
  gcrManifestUrl,
  gcrRegistryHost,
  gcrTokenUrl,
  isGcrRegistryHost,
  ContainerEgressError,
} from '../container.egress';
import { allowlistedGcpTokenUrl, GCP_TOKEN_URL, GcpEgressError } from '../gcp.egress';
import { exchangeGcpAccessToken } from '../gcp.jwt';
import { EGRESS_GCR_REGISTRY, registryPullFetch } from './pull-egress';
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
export const GCR_FETCH = Symbol('GCR_FETCH');

export interface GcrImagePuller {
  pull(
    ref: GcrImageRef,
    credentials: GcpCredentials,
    checkDeadline: () => boolean,
  ): Promise<ImagePull>;
}

/**
 * In-process OCI pull from allowlisted `{location}-docker.pkg.dev`.
 * Auth is a Google OAuth access token from `oauth2.googleapis.com` (that
 * host stays on its own allowlisted fetch — it is not this circuit), then
 * a docker registry token on the pinned AR docker host. Docker token,
 * manifest, and blob HTTP use `@ctem/resilience` (`egress:gcr-registry`).
 * No docker / podman / skopeo / crane. Layer blobs are cached by digest for the
 * life of the worker. Pull is by digest only.
 */
@Injectable()
export class GcrRegistry implements GcrImagePuller {
  private readonly layerCache = new Map<string, LayerSnapshot>();
  private readonly fetchImpl: typeof fetch;

  constructor(@Optional() @Inject(GCR_FETCH) fetchImpl?: typeof fetch) {
    this.fetchImpl = fetchImpl ?? fetch;
  }

  async pull(
    ref: GcrImageRef,
    credentials: GcpCredentials,
    checkDeadline: () => boolean,
  ): Promise<ImagePull> {
    if (!checkDeadline()) {
      throw new ContainerPullError('Job deadline exceeded before GCR pull');
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
      owner: ref.projectId,
      name: `${ref.repository}/${ref.image}`,
      layers: snapshots,
    };
  }

  private async registryToken(
    ref: GcrImageRef,
    credentials: GcpCredentials,
    checkDeadline: () => boolean,
  ): Promise<string> {
    if (!checkDeadline()) {
      throw new ContainerPullError('Job deadline exceeded during GCR token exchange');
    }
    // Belt: never send the service-account JWT off oauth2.googleapis.com.
    allowlistedGcpTokenUrl(GCP_TOKEN_URL);
    let googleToken: string;
    try {
      googleToken = await exchangeGcpAccessToken(credentials, this.fetchImpl);
    } catch (err) {
      if (err instanceof GcpEgressError || err instanceof ContainerEgressError) throw err;
      throw new ContainerPullError(
        `GCR Google token exchange failed: ${err instanceof Error ? err.message : String(err)} — refusing pull`,
      );
    }
    if (!checkDeadline()) {
      throw new ContainerPullError('Job deadline exceeded during GCR docker token exchange');
    }

    const url = gcrTokenUrl(ref.location, ref.projectId, ref.repository, ref.image);
    const res = await registryPullFetch(
      EGRESS_GCR_REGISTRY,
      url,
      {
        method: 'GET',
        headers: {
          'user-agent': 'ctem-platform',
          authorization: `Bearer ${googleToken}`,
        },
      },
      this.fetchImpl,
    );
    if (res.status === 401 || res.status === 403) {
      throw new ContainerPullError(
        `GCR docker token exchange returned ${res.status} — refusing pull`,
      );
    }
    if (!res.ok) {
      throw new ContainerPullError(
        `GCR docker token exchange returned ${res.status} — refusing pull`,
      );
    }
    let json: unknown;
    try {
      json = await res.json();
    } catch {
      throw new ContainerPullError('GCR docker token exchange was not JSON — refusing pull');
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
      throw new ContainerPullError('GCR docker token exchange returned no token — refusing pull');
    }
    return token.trim();
  }

  private async getManifest(
    ref: GcrImageRef,
    digest: string,
    registryToken: string,
    checkDeadline: () => boolean,
  ): Promise<unknown> {
    if (!checkDeadline())
      throw new ContainerPullError('Job deadline exceeded during manifest pull');
    const url = gcrManifestUrl(ref.location, ref.projectId, ref.repository, ref.image, digest);
    const res = await this.gcrGet(url, ref, registryToken, MANIFEST_ACCEPT);
    if (res.status === 401 || res.status === 403) {
      throw new ContainerPullError(`GCR manifest GET returned ${res.status} — refusing pull`);
    }
    if (!res.ok) {
      throw new ContainerPullError(`GCR manifest GET returned ${res.status} — refusing pull`);
    }
    return res.json();
  }

  private async resolvePlatformManifest(
    ref: GcrImageRef,
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
          'GCR index has no linux platform manifest — refusing incomplete inventory',
        );
      }
      const nested = await this.getManifest(ref, chosen.digest, registryToken, checkDeadline);
      return this.requireImageManifest(nested);
    }
    return this.requireImageManifest(json);
  }

  private requireImageManifest(json: unknown): OciManifest {
    if (!json || typeof json !== 'object') {
      throw new ContainerPullError('GCR manifest was not JSON — refusing incomplete inventory');
    }
    const rec = json as OciManifest;
    if (!Array.isArray(rec.layers)) {
      throw new ContainerPullError(
        'GCR image manifest missing layers — refusing incomplete inventory',
      );
    }
    return rec;
  }

  private async getBlob(
    ref: GcrImageRef,
    digest: string,
    registryToken: string,
    checkDeadline: () => boolean,
  ): Promise<Buffer> {
    if (!checkDeadline()) throw new ContainerPullError('Job deadline exceeded during blob pull');
    const url = gcrBlobUrl(ref.location, ref.projectId, ref.repository, ref.image, digest);
    const res = await this.gcrGet(url, ref, registryToken, 'application/octet-stream', true);
    if (res.status === 401 || res.status === 403) {
      throw new ContainerPullError(`GCR blob GET returned ${res.status} — refusing pull`);
    }
    if (!res.ok) {
      throw new ContainerPullError(`GCR blob GET returned ${res.status} — refusing pull`);
    }
    return Buffer.from(await res.arrayBuffer());
  }

  /**
   * GET on `{location}-docker.pkg.dev` with the docker registry bearer.
   * Blob redirects to path-style GCS are followed without the bearer
   * (pre-signed Location). Never use a tenant pkg.dev / registry URL.
   */
  private async gcrGet(
    url: string,
    ref: GcrImageRef,
    registryToken: string,
    accept: string,
    followBlobRedirect = false,
  ): Promise<Response> {
    const dest = allowlistedGcrRegistryUrl(url, ref.location);
    const headers: Record<string, string> = {
      accept,
      'user-agent': 'ctem-platform',
      authorization: `Bearer ${registryToken}`,
    };
    const res = await registryPullFetch(
      EGRESS_GCR_REGISTRY,
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
      throw new ContainerPullError('GCR blob redirect missing Location — refusing pull');
    }
    const next = allowlistedGcrBlobRedirect(new URL(location, dest).toString(), ref.location);
    const nextHeaders: Record<string, string> = { accept, 'user-agent': 'ctem-platform' };
    const nextHost = new URL(next).hostname;
    if (isGcrRegistryHost(nextHost, ref.location)) {
      nextHeaders.authorization = `Bearer ${registryToken}`;
    }
    return registryPullFetch(
      EGRESS_GCR_REGISTRY,
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

export { ContainerEgressError, ContainerPullError, gcrRegistryHost };
