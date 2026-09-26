import { Inject, Injectable, Optional } from '@nestjs/common';
import type { AzureCredentials } from '../container.credential';
import type { AcrImageRef } from '../container.identity';
import {
  acrBlobUrl,
  acrManifestUrl,
  acrOauthExchangeUrl,
  acrOauthTokenUrl,
  acrRegistryHost,
  allowlistedAcrBlobRedirect,
  allowlistedAcrOauthUrl,
  allowlistedAcrRegistryUrl,
  isAcrRegistryHost,
  ContainerEgressError,
} from '../container.egress';
import {
  ACR_AAD_SCOPE,
  AzureEgressError,
  allowlistedAzureTokenUrl,
  azureTokenUrl,
} from '../azure.egress';
import { exchangeAzureAccessToken } from '../azure.token';
import { EGRESS_ACR_REGISTRY, registryPullFetch } from './pull-egress';
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
export const ACR_FETCH = Symbol('ACR_FETCH');

export interface AcrImagePuller {
  pull(
    ref: AcrImageRef,
    credentials: AzureCredentials,
    checkDeadline: () => boolean,
  ): Promise<ImagePull>;
}

/**
 * In-process OCI pull from allowlisted `{registry}.azurecr.io`.
 * Auth is an AAD client-credentials token from `login.microsoftonline.com`
 * (ACR audience; that host stays on its own allowlisted fetch — it is not
 * this circuit), then ACR oauth exchange + access token on the pinned
 * `{registry}.azurecr.io` host. ACR oauth, manifest, and blob HTTP use
 * `@ctem/resilience` (`egress:acr-registry`). No docker / podman / skopeo / crane.
 * Layer blobs are cached by digest for the life of the worker. Pull is
 * by digest only.
 */
@Injectable()
export class AcrRegistry implements AcrImagePuller {
  private readonly layerCache = new Map<string, LayerSnapshot>();
  private readonly fetchImpl: typeof fetch;

  constructor(@Optional() @Inject(ACR_FETCH) fetchImpl?: typeof fetch) {
    this.fetchImpl = fetchImpl ?? fetch;
  }

  async pull(
    ref: AcrImageRef,
    credentials: AzureCredentials,
    checkDeadline: () => boolean,
  ): Promise<ImagePull> {
    if (!checkDeadline()) {
      throw new ContainerPullError('Job deadline exceeded before ACR pull');
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
      owner: ref.registry,
      name: ref.repository,
      layers: snapshots,
    };
  }

  private async registryToken(
    ref: AcrImageRef,
    credentials: AzureCredentials,
    checkDeadline: () => boolean,
  ): Promise<string> {
    if (!checkDeadline()) {
      throw new ContainerPullError('Job deadline exceeded during ACR token exchange');
    }
    // Belt: never send AZURE_CLIENT_SECRET off login.microsoftonline.com.
    allowlistedAzureTokenUrl(azureTokenUrl(credentials.tenantId));
    let aadToken: string;
    try {
      aadToken = await exchangeAzureAccessToken(credentials, this.fetchImpl, ACR_AAD_SCOPE);
    } catch (err) {
      if (err instanceof AzureEgressError || err instanceof ContainerEgressError) throw err;
      throw new ContainerPullError(
        `ACR Azure token exchange failed: ${err instanceof Error ? err.message : String(err)} — refusing pull`,
      );
    }
    if (!checkDeadline()) {
      throw new ContainerPullError('Job deadline exceeded during ACR oauth exchange');
    }

    const refreshToken = await this.exchangeRefreshToken(ref, credentials, aadToken);
    if (!checkDeadline()) {
      throw new ContainerPullError('Job deadline exceeded during ACR oauth token');
    }
    return this.accessToken(ref, refreshToken);
  }

  private async exchangeRefreshToken(
    ref: AcrImageRef,
    credentials: AzureCredentials,
    aadToken: string,
  ): Promise<string> {
    const url = acrOauthExchangeUrl(ref.registry);
    allowlistedAcrOauthUrl(url, ref.registry);
    const body = new URLSearchParams({
      grant_type: 'access_token',
      service: acrRegistryHost(ref.registry),
      tenant: credentials.tenantId,
      access_token: aadToken,
    }).toString();
    const res = await registryPullFetch(
      EGRESS_ACR_REGISTRY,
      url,
      {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          'user-agent': 'ctem-platform',
        },
        body,
      },
      this.fetchImpl,
    );
    if (res.status === 401 || res.status === 403) {
      throw new ContainerPullError(`ACR oauth exchange returned ${res.status} — refusing pull`);
    }
    if (!res.ok) {
      throw new ContainerPullError(`ACR oauth exchange returned ${res.status} — refusing pull`);
    }
    let json: unknown;
    try {
      json = await res.json();
    } catch {
      throw new ContainerPullError('ACR oauth exchange was not JSON — refusing pull');
    }
    const rec = json && typeof json === 'object' ? (json as { refresh_token?: unknown }) : {};
    if (typeof rec.refresh_token !== 'string' || !rec.refresh_token.trim()) {
      throw new ContainerPullError('ACR oauth exchange returned no refresh_token — refusing pull');
    }
    return rec.refresh_token.trim();
  }

  private async accessToken(ref: AcrImageRef, refreshToken: string): Promise<string> {
    const url = acrOauthTokenUrl(ref.registry);
    allowlistedAcrOauthUrl(url, ref.registry);
    const body = new URLSearchParams({
      grant_type: 'refresh_token',
      service: acrRegistryHost(ref.registry),
      scope: `repository:${ref.repository}:pull`,
      refresh_token: refreshToken,
    }).toString();
    const res = await registryPullFetch(
      EGRESS_ACR_REGISTRY,
      url,
      {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          'user-agent': 'ctem-platform',
        },
        body,
      },
      this.fetchImpl,
    );
    if (res.status === 401 || res.status === 403) {
      throw new ContainerPullError(`ACR oauth token returned ${res.status} — refusing pull`);
    }
    if (!res.ok) {
      throw new ContainerPullError(`ACR oauth token returned ${res.status} — refusing pull`);
    }
    let json: unknown;
    try {
      json = await res.json();
    } catch {
      throw new ContainerPullError('ACR oauth token was not JSON — refusing pull');
    }
    const rec = json && typeof json === 'object' ? (json as { access_token?: unknown }) : {};
    if (typeof rec.access_token !== 'string' || !rec.access_token.trim()) {
      throw new ContainerPullError('ACR oauth token returned no access_token — refusing pull');
    }
    return rec.access_token.trim();
  }

  private async getManifest(
    ref: AcrImageRef,
    digest: string,
    registryToken: string,
    checkDeadline: () => boolean,
  ): Promise<unknown> {
    if (!checkDeadline())
      throw new ContainerPullError('Job deadline exceeded during manifest pull');
    const url = acrManifestUrl(ref.registry, ref.repository, digest);
    const res = await this.acrGet(url, ref, registryToken, MANIFEST_ACCEPT);
    if (res.status === 401 || res.status === 403) {
      throw new ContainerPullError(`ACR manifest GET returned ${res.status} — refusing pull`);
    }
    if (!res.ok) {
      throw new ContainerPullError(`ACR manifest GET returned ${res.status} — refusing pull`);
    }
    return res.json();
  }

  private async resolvePlatformManifest(
    ref: AcrImageRef,
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
          'ACR index has no linux platform manifest — refusing incomplete inventory',
        );
      }
      const nested = await this.getManifest(ref, chosen.digest, registryToken, checkDeadline);
      return this.requireImageManifest(nested);
    }
    return this.requireImageManifest(json);
  }

  private requireImageManifest(json: unknown): OciManifest {
    if (!json || typeof json !== 'object') {
      throw new ContainerPullError('ACR manifest was not JSON — refusing incomplete inventory');
    }
    const rec = json as OciManifest;
    if (!Array.isArray(rec.layers)) {
      throw new ContainerPullError(
        'ACR image manifest missing layers — refusing incomplete inventory',
      );
    }
    return rec;
  }

  private async getBlob(
    ref: AcrImageRef,
    digest: string,
    registryToken: string,
    checkDeadline: () => boolean,
  ): Promise<Buffer> {
    if (!checkDeadline()) throw new ContainerPullError('Job deadline exceeded during blob pull');
    const url = acrBlobUrl(ref.registry, ref.repository, digest);
    const res = await this.acrGet(url, ref, registryToken, 'application/octet-stream', true);
    if (res.status === 401 || res.status === 403) {
      throw new ContainerPullError(`ACR blob GET returned ${res.status} — refusing pull`);
    }
    if (!res.ok) {
      throw new ContainerPullError(`ACR blob GET returned ${res.status} — refusing pull`);
    }
    return Buffer.from(await res.arrayBuffer());
  }

  /**
   * GET on `{registry}.azurecr.io` with the ACR registry bearer. Blob
   * redirects stay on that exact host; never use a tenant loginServer.
   */
  private async acrGet(
    url: string,
    ref: AcrImageRef,
    registryToken: string,
    accept: string,
    followBlobRedirect = false,
  ): Promise<Response> {
    const dest = allowlistedAcrRegistryUrl(url, ref.registry);
    const headers: Record<string, string> = {
      accept,
      'user-agent': 'ctem-platform',
      authorization: `Bearer ${registryToken}`,
    };
    const res = await registryPullFetch(
      EGRESS_ACR_REGISTRY,
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
      throw new ContainerPullError('ACR blob redirect missing Location — refusing pull');
    }
    const next = allowlistedAcrBlobRedirect(new URL(location, dest).toString(), ref.registry);
    const nextHeaders: Record<string, string> = { accept, 'user-agent': 'ctem-platform' };
    const nextHost = new URL(next).hostname;
    if (isAcrRegistryHost(nextHost, ref.registry)) {
      nextHeaders.authorization = `Bearer ${registryToken}`;
    }
    return registryPullFetch(
      EGRESS_ACR_REGISTRY,
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

export { ContainerEgressError, ContainerPullError, acrRegistryHost };
