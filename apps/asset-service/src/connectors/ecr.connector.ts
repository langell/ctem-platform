import { Injectable } from '@nestjs/common';
import { z } from 'zod';
import { rootLogger } from '@ctem/observability';
import type { UpsertAssetRequest } from '@ctem/contracts';
import type { AssetConnector, DiscoveryContext } from './connector.registry';
import { requireAwsCredentials, type AwsCredentials } from './credentials';
import { AWS_REGION_RE, allowlistedAwsUrl, awsServiceUrl } from './aws.egress';
import { signAwsRequest } from './aws.sigv4';
import { xmlTag } from './aws.xml';
import { allowlistedEcrApiUrl, ecrApiUrl, refuseTenantWritableEndpoint } from './ecr.egress';

export const EcrConnectorConfig = z
  .object({
    /** Region to inventory. This is an AWS region id, not an API host. */
    region: z.string().regex(AWS_REGION_RE, 'must be an AWS region identifier').optional(),
    /** Additional regions; unioned with `region`. At least one region is required. */
    regions: z
      .array(z.string().regex(AWS_REGION_RE, 'must be an AWS region identifier'))
      .optional(),
    /** Optional expected account; mismatch fails closed so we do not persist the wrong tenant. */
    accountId: z
      .string()
      .regex(/^\d{12}$/)
      .optional(),
    /** Optional allowlist of repository names; omit to inventory everything. */
    repositories: z.array(z.string().min(1)).optional(),
  })
  .superRefine((value, ctx) => {
    if (!value.region && !(value.regions && value.regions.length > 0)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'region or regions is required',
        path: ['region'],
      });
    }
  });
export type EcrConnectorConfig = z.infer<typeof EcrConnectorConfig>;

export const ECR_PER_PAGE = 100;
export const ECR_MAX_PAGES = 20;

const ECR_JSON_TARGET_PREFIX = 'AmazonEC2ContainerRegistry_V20150921';

/** OCI identity is the content digest, never a mutable tag. */
export const SHA256_DIGEST_RE = /^sha256:[a-f0-9]{64}$/i;

export interface EcrRepository {
  name: string;
  registryId?: string;
  arn?: string;
  uri?: string;
}

export interface EcrImage {
  accountId: string;
  region: string;
  repositoryName: string;
  digest: string;
  tags: string[];
  repositoryArn?: string;
  repositoryUri?: string;
  imagePushedAt?: string | number;
  imageSizeInBytes?: number;
}

export function configuredRegions(config: EcrConnectorConfig): string[] {
  const seen = new Set<string>();
  if (config.region) seen.add(config.region);
  for (const region of config.regions ?? []) seen.add(region);
  return [...seen];
}

export function parseCallerAccount(xml: string): string {
  const account = xmlTag(xml, 'Account');
  if (!account || !/^\d{12}$/.test(account)) {
    throw new Error('AWS STS GetCallerIdentity did not return a 12-digit account id');
  }
  return account;
}

export function jsonNextToken(json: unknown): string | undefined {
  if (!json || typeof json !== 'object' || Array.isArray(json)) return undefined;
  const token = (json as { nextToken?: unknown }).nextToken;
  if (typeof token !== 'string') return undefined;
  const trimmed = token.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

export function parseRepositories(json: unknown): EcrRepository[] {
  const obj = jsonObjectOrThrow(json, 'repositories');
  const repos: EcrRepository[] = [];
  for (const raw of jsonArrayField(obj, 'repositories', 'repositories')) {
    if (!raw || typeof raw !== 'object') continue;
    const item = raw as {
      repositoryName?: unknown;
      registryId?: unknown;
      repositoryArn?: unknown;
      repositoryUri?: unknown;
    };
    if (typeof item.repositoryName !== 'string' || item.repositoryName.length === 0) continue;
    repos.push({
      name: item.repositoryName,
      registryId: typeof item.registryId === 'string' ? item.registryId : undefined,
      arn: typeof item.repositoryArn === 'string' ? item.repositoryArn : undefined,
      uri: typeof item.repositoryUri === 'string' ? item.repositoryUri : undefined,
    });
  }
  return repos;
}

export function parseImages(
  json: unknown,
): Array<{ digest: string; tags: string[]; pushedAt?: string | number; size?: number }> {
  const obj = jsonObjectOrThrow(json, 'images');
  const images: Array<{
    digest: string;
    tags: string[];
    pushedAt?: string | number;
    size?: number;
  }> = [];
  for (const raw of jsonArrayField(obj, 'imageDetails', 'images')) {
    if (!raw || typeof raw !== 'object') continue;
    const item = raw as {
      imageDigest?: unknown;
      imageTags?: unknown;
      imagePushedAt?: unknown;
      imageSizeInBytes?: unknown;
    };
    const digest = imageDigest(item.imageDigest);
    if (!digest) continue;
    const parsed: { digest: string; tags: string[]; pushedAt?: string | number; size?: number } = {
      digest,
      tags: imageTags(item.imageTags),
    };
    if (typeof item.imagePushedAt === 'string' || typeof item.imagePushedAt === 'number') {
      parsed.pushedAt = item.imagePushedAt;
    }
    if (typeof item.imageSizeInBytes === 'number') parsed.size = item.imageSizeInBytes;
    images.push(parsed);
  }
  return images;
}

export function imageDigest(raw: unknown): string | undefined {
  if (typeof raw !== 'string' || !SHA256_DIGEST_RE.test(raw)) return undefined;
  return raw.toLowerCase();
}

export function imageTags(raw: unknown): string[] {
  if (!Array.isArray(raw)) return [];
  return raw.filter((t): t is string => typeof t === 'string' && t.length > 0);
}

export function imageToAsset(image: EcrImage): UpsertAssetRequest {
  return {
    kind: 'container_image',
    externalKey: `ecr:${image.accountId}/${image.repositoryName}@${image.digest}`,
    name: image.repositoryName,
    source: 'ecr',
    exposure: 'internal',
    attributes: {
      accountId: image.accountId,
      region: image.region,
      repository: image.repositoryName,
      digest: image.digest,
      tags: image.tags,
      repositoryArn: image.repositoryArn ?? null,
      repositoryUri: image.repositoryUri ?? null,
      imagePushedAt: image.imagePushedAt ?? null,
      imageSizeInBytes: image.imageSizeInBytes ?? null,
    },
  };
}

function jsonObjectOrThrow(json: unknown, label: string): Record<string, unknown> {
  if (!json || typeof json !== 'object' || Array.isArray(json)) {
    throw new Error(`ECR ${label} listing was not a JSON object — refusing incomplete inventory`);
  }
  return json as Record<string, unknown>;
}

function jsonArrayField(obj: Record<string, unknown>, field: string, label: string): unknown[] {
  const value = obj[field];
  if (value == null) return [];
  if (!Array.isArray(value)) {
    throw new Error(`ECR ${label} listing was not a JSON array — refusing incomplete inventory`);
  }
  return value;
}

/**
 * Container-image inventory via Amazon ECR (`DescribeRepositories` +
 * `DescribeImages`). Same persistence path as GHCR/AWS: discover →
 * UpsertAssetRequest → scheduler upsert + archiveStale scoped per
 * integrationId.
 *
 * Hosts are hardcoded to allowlisted `api.ecr.{region}.amazonaws.com` (and
 * STS for caller identity). Tenant config cannot set a registry/API host.
 * Credentials are platform-operated `env:AWS_*` and fail closed when
 * missing — there is no public-listing fallback.
 *
 * Identity is the image digest. Tags live in attributes so a retag does not
 * fork assets. This connector does not pull layers or fetch OCI blobs —
 * inventory is the ECR JSON API only. Layer pull is scanner-container-iac
 * for `ecr:{account}/{repo}@{digest}` identities.
 *
 * This connector always full-scans. `ctx.orgId` is unused (tenancy is applied
 * by the scheduler on persist) and `ctx.since` is unused — ECR list APIs do
 * not offer a reliable incremental window for this inventory.
 */
@Injectable()
export class EcrConnector implements AssetConnector {
  readonly provider = 'ecr';
  readonly assetKinds = ['container_image'];
  private readonly log = rootLogger.child({ component: 'ecr-connector' });

  async *discover(ctx: DiscoveryContext): AsyncIterable<UpsertAssetRequest> {
    refuseTenantWritableEndpoint(ctx.config);
    const config = EcrConnectorConfig.parse(ctx.config);
    const creds = requireAwsCredentials(ctx.credentialRef);
    const regions = configuredRegions(config);
    const stsRegion = config.region ?? regions[0]!;

    const accountId = await this.callerAccount(stsRegion, creds);
    if (config.accountId && config.accountId !== accountId) {
      throw new Error(
        `AWS account ${accountId} does not match configured accountId ${config.accountId} — refusing to inventory`,
      );
    }

    const allow = config.repositories?.length ? new Set(config.repositories) : null;
    let seen = 0;
    const yielded = new Set<string>();

    for (const region of regions) {
      for await (const repo of this.listRepositories(region, creds, accountId)) {
        if (allow && !allow.has(repo.name)) continue;
        if (repo.registryId && repo.registryId !== accountId) continue;

        for await (const image of this.listImages(region, creds, accountId, repo.name)) {
          const asset = imageToAsset({
            accountId,
            region,
            repositoryName: repo.name,
            digest: image.digest,
            tags: image.tags,
            repositoryArn: repo.arn,
            repositoryUri: repo.uri,
            imagePushedAt: image.pushedAt,
            imageSizeInBytes: image.size,
          });
          if (yielded.has(asset.externalKey)) continue;
          yielded.add(asset.externalKey);
          seen += 1;
          yield asset;
        }
      }
    }

    this.log.info({ accountId, regions, images: seen }, 'ecr discovery complete');
  }

  private async callerAccount(region: string, creds: AwsCredentials): Promise<string> {
    const url = awsServiceUrl('sts', region);
    const body = new URLSearchParams({
      Action: 'GetCallerIdentity',
      Version: '2011-06-15',
    }).toString();
    const signed = signAwsRequest({
      method: 'POST',
      url,
      region,
      service: 'sts',
      credentials: creds,
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body,
    });
    const xml = await this.send(signed, 'sts', 'GetCallerIdentity', 'sts');
    return parseCallerAccount(xml);
  }

  private async *listRepositories(
    region: string,
    creds: AwsCredentials,
    accountId: string,
  ): AsyncIterable<EcrRepository> {
    yield* this.pagedJson(
      region,
      creds,
      'DescribeRepositories',
      { registryId: accountId },
      (json) => parseRepositories(json),
      'repositories',
    );
  }

  private async *listImages(
    region: string,
    creds: AwsCredentials,
    accountId: string,
    repositoryName: string,
  ): AsyncIterable<{ digest: string; tags: string[]; pushedAt?: string | number; size?: number }> {
    yield* this.pagedJson(
      region,
      creds,
      'DescribeImages',
      { registryId: accountId, repositoryName },
      (json) => parseImages(json),
      `images for ${repositoryName}`,
    );
  }

  /**
   * Complete-signal is missing nextToken, not page length. A last page of
   * ECR_PER_PAGE with no token succeeds. Only a leftover nextToken after the
   * cap is truncated / fail-closed (so archiveStale cannot run on a partial
   * list).
   */
  private async *pagedJson<T>(
    region: string,
    creds: AwsCredentials,
    action: 'DescribeRepositories' | 'DescribeImages',
    params: Record<string, string>,
    mapPage: (json: unknown) => T[],
    label: string,
  ): AsyncIterable<T> {
    let token: string | undefined;
    for (let page = 1; page <= ECR_MAX_PAGES; page++) {
      const json = await this.ecrJson(region, creds, action, {
        ...params,
        ...(token ? { nextToken: token } : {}),
      });
      for (const item of mapPage(json)) yield item;
      token = jsonNextToken(json);
      if (!token) return;
      if (page === ECR_MAX_PAGES) this.failTruncated(label);
    }
  }

  private failTruncated(label: string): never {
    this.log.error(
      { pages: ECR_MAX_PAGES, perPage: ECR_PER_PAGE, label },
      'ecr listing truncated at page cap',
    );
    throw new Error(
      `ECR listing truncated at ${ECR_MAX_PAGES * ECR_PER_PAGE} ${label} (page cap ${ECR_MAX_PAGES}); refusing to archive unseen assets`,
    );
  }

  private async ecrJson(
    region: string,
    creds: AwsCredentials,
    action: 'DescribeRepositories' | 'DescribeImages',
    params: Record<string, string>,
  ): Promise<unknown> {
    const payload: Record<string, unknown> = {
      maxResults: ECR_PER_PAGE,
      ...params,
    };
    const body = JSON.stringify(payload);
    const signed = signAwsRequest({
      method: 'POST',
      url: ecrApiUrl(region),
      region,
      service: 'ecr',
      credentials: creds,
      headers: {
        'content-type': 'application/x-amz-json-1.1',
        'x-amz-target': `${ECR_JSON_TARGET_PREFIX}.${action}`,
      },
      body,
    });
    const text = await this.send(signed, 'ecr', action, 'ecr');
    try {
      return JSON.parse(text) as unknown;
    } catch {
      throw new Error(`ECR ${action} listing was not JSON — refusing incomplete inventory`);
    }
  }

  private async send(
    signed: { url: string; method: 'GET' | 'POST'; headers: Record<string, string>; body?: string },
    service: 'ecr' | 'sts',
    action: string,
    kind: 'ecr' | 'sts',
  ): Promise<string> {
    // Belt: never send keys off the allowlist even if a caller built `signed`.
    if (kind === 'ecr') allowlistedEcrApiUrl(signed.url);
    else allowlistedAwsUrl(signed.url);
    const res = await fetch(signed.url, {
      method: signed.method,
      headers: signed.headers,
      body: signed.method === 'POST' ? signed.body : undefined,
      signal: AbortSignal.timeout(20_000),
    });
    if (!res.ok) {
      throw new Error(`ECR ${service} API returned ${res.status} for ${action}`);
    }
    return res.text();
  }
}
