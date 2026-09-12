import { Inject, Injectable, Optional } from '@nestjs/common';
import type { AwsCredentials } from '../container.credential';
import type { EcrImageRef } from '../container.identity';
import {
  allowlistedEcrApiUrl,
  allowlistedEcrBlobRedirect,
  allowlistedEcrRegistryUrl,
  ecrApiUrl,
  ecrBlobUrl,
  ecrManifestUrl,
  ecrRegistryHost,
  isEcrRegistryHost,
  ContainerEgressError,
} from '../container.egress';
import { signAwsRequest } from '../aws.sigv4';
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

const ECR_JSON_TARGET_PREFIX = 'AmazonEC2ContainerRegistry_V20150921';

/** Injection token for overriding the fetch implementation (tests, egress shims). */
export const ECR_FETCH = Symbol('ECR_FETCH');

export interface EcrImagePuller {
  pull(
    ref: EcrImageRef,
    credentials: AwsCredentials,
    checkDeadline: () => boolean,
  ): Promise<ImagePull>;
}

/**
 * In-process OCI pull from allowlisted `{account}.dkr.ecr.{region}.amazonaws.com`.
 * Auth is GetAuthorizationToken on `api.ecr.{region}.amazonaws.com` via SigV4.
 * No docker/podman/skopeo/crane. Layer blobs are cached by digest for the
 * life of the worker. Pull is by digest only.
 */
@Injectable()
export class EcrRegistry implements EcrImagePuller {
  private readonly layerCache = new Map<string, LayerSnapshot>();
  private readonly fetchImpl: typeof fetch;

  constructor(@Optional() @Inject(ECR_FETCH) fetchImpl?: typeof fetch) {
    this.fetchImpl = fetchImpl ?? fetch;
  }

  async pull(
    ref: EcrImageRef,
    credentials: AwsCredentials,
    checkDeadline: () => boolean,
  ): Promise<ImagePull> {
    if (!checkDeadline()) {
      throw new ContainerPullError('Job deadline exceeded before ECR pull');
    }

    const registryToken = await this.authorizationToken(ref, credentials, checkDeadline);
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

    return {
      digest: ref.digest,
      owner: ref.accountId,
      name: ref.repositoryName,
      layers: snapshots,
    };
  }

  private async authorizationToken(
    ref: EcrImageRef,
    credentials: AwsCredentials,
    checkDeadline: () => boolean,
  ): Promise<string> {
    if (!checkDeadline()) {
      throw new ContainerPullError('Job deadline exceeded during ECR GetAuthorizationToken');
    }
    const body = JSON.stringify({ registryIds: [ref.accountId] });
    const signed = signAwsRequest({
      method: 'POST',
      url: ecrApiUrl(ref.region),
      region: ref.region,
      service: 'ecr',
      credentials,
      headers: {
        'content-type': 'application/x-amz-json-1.1',
        'x-amz-target': `${ECR_JSON_TARGET_PREFIX}.GetAuthorizationToken`,
      },
      body,
    });
    // Belt: never send AWS_* keys off the ECR JSON API allowlist.
    allowlistedEcrApiUrl(signed.url);
    const res = await this.fetchImpl(signed.url, {
      method: 'POST',
      headers: signed.headers,
      body: signed.body,
      signal: AbortSignal.timeout(20_000),
    });
    if (res.status === 401 || res.status === 403) {
      throw new ContainerPullError(`ECR GetAuthorizationToken returned ${res.status} — refusing pull`);
    }
    if (!res.ok) {
      throw new ContainerPullError(`ECR GetAuthorizationToken returned ${res.status} — refusing pull`);
    }
    let json: unknown;
    try {
      json = await res.json();
    } catch {
      throw new ContainerPullError('ECR GetAuthorizationToken was not JSON — refusing pull');
    }
    const token = authorizationTokenFrom(json);
    if (!token) {
      throw new ContainerPullError('ECR GetAuthorizationToken returned no token — refusing pull');
    }
    return token;
  }

  private async getManifest(
    ref: EcrImageRef,
    digest: string,
    registryToken: string,
    checkDeadline: () => boolean,
  ): Promise<unknown> {
    if (!checkDeadline()) throw new ContainerPullError('Job deadline exceeded during manifest pull');
    const url = ecrManifestUrl(ref.accountId, ref.region, ref.repositoryName, digest);
    const res = await this.ecrGet(url, ref, registryToken, MANIFEST_ACCEPT);
    if (res.status === 401 || res.status === 403) {
      throw new ContainerPullError(`ECR manifest GET returned ${res.status} — refusing pull`);
    }
    if (!res.ok) {
      throw new ContainerPullError(`ECR manifest GET returned ${res.status} — refusing pull`);
    }
    return res.json();
  }

  private async resolvePlatformManifest(
    ref: EcrImageRef,
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
        throw new ContainerPullError('ECR index has no linux platform manifest — refusing incomplete inventory');
      }
      const nested = await this.getManifest(ref, chosen.digest, registryToken, checkDeadline);
      return this.requireImageManifest(nested);
    }
    return this.requireImageManifest(json);
  }

  private requireImageManifest(json: unknown): OciManifest {
    if (!json || typeof json !== 'object') {
      throw new ContainerPullError('ECR manifest was not JSON — refusing incomplete inventory');
    }
    const rec = json as OciManifest;
    if (!Array.isArray(rec.layers)) {
      throw new ContainerPullError('ECR image manifest missing layers — refusing incomplete inventory');
    }
    return rec;
  }

  private async getBlob(
    ref: EcrImageRef,
    digest: string,
    registryToken: string,
    checkDeadline: () => boolean,
  ): Promise<Buffer> {
    if (!checkDeadline()) throw new ContainerPullError('Job deadline exceeded during blob pull');
    const url = ecrBlobUrl(ref.accountId, ref.region, ref.repositoryName, digest);
    const res = await this.ecrGet(url, ref, registryToken, 'application/octet-stream', true);
    if (res.status === 401 || res.status === 403) {
      throw new ContainerPullError(`ECR blob GET returned ${res.status} — refusing pull`);
    }
    if (!res.ok) {
      throw new ContainerPullError(`ECR blob GET returned ${res.status} — refusing pull`);
    }
    return Buffer.from(await res.arrayBuffer());
  }

  /**
   * GET on `{account}.dkr.ecr.{region}.amazonaws.com` with ECR Basic auth.
   * Blob redirects to regional S3 are followed without the Basic token
   * (pre-signed Location). Never use GetAuthorizationToken's proxyEndpoint.
   */
  private async ecrGet(
    url: string,
    ref: EcrImageRef,
    registryToken: string,
    accept: string,
    followBlobRedirect = false,
  ): Promise<Response> {
    const dest = allowlistedEcrRegistryUrl(url, ref.accountId, ref.region);
    const headers: Record<string, string> = {
      accept,
      'user-agent': 'ctem-platform',
      authorization: `Basic ${registryToken}`,
    };
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
      throw new ContainerPullError('ECR blob redirect missing Location — refusing pull');
    }
    const next = allowlistedEcrBlobRedirect(new URL(location, dest).toString(), ref.accountId, ref.region);
    const nextHeaders: Record<string, string> = { accept, 'user-agent': 'ctem-platform' };
    const nextHost = new URL(next).hostname;
    if (isEcrRegistryHost(nextHost, ref.accountId, ref.region)) {
      nextHeaders.authorization = `Basic ${registryToken}`;
    }
    return this.fetchImpl(next, {
      method: 'GET',
      headers: nextHeaders,
      redirect: 'error',
      signal: AbortSignal.timeout(60_000),
    });
  }
}

function authorizationTokenFrom(json: unknown): string | undefined {
  if (!json || typeof json !== 'object') return undefined;
  const data = (json as { authorizationData?: unknown }).authorizationData;
  if (!Array.isArray(data) || data.length === 0) return undefined;
  const first = data[0];
  if (!first || typeof first !== 'object') return undefined;
  const token = (first as { authorizationToken?: unknown }).authorizationToken;
  if (typeof token !== 'string' || !token.trim()) return undefined;
  return token.trim();
}

export { ContainerEgressError, ContainerPullError, ecrRegistryHost };
