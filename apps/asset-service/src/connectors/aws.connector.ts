import { Injectable } from '@nestjs/common';
import { z } from 'zod';
import { rootLogger } from '@ctem/observability';
import type { UpsertAssetRequest } from '@ctem/contracts';
import type { AssetConnector, DiscoveryContext } from './connector.registry';
import { requireAwsCredentials, type AwsCredentials } from './credentials';
import {
  AWS_REGION_RE,
  allowlistedAwsUrl,
  awsServiceUrl,
  refuseTenantWritableEndpoint,
  type AwsService,
} from './aws.egress';
import { signAwsRequest } from './aws.sigv4';
import { extractTagBlocks, xmlIsTruncated, xmlNextToken, xmlTag, xmlTags } from './aws.xml';

export const AwsResourceType = z.enum([
  'ec2_instance',
  's3_bucket',
  'security_group',
  'elastic_ip',
]);
export type AwsResourceType = z.infer<typeof AwsResourceType>;

export const AwsConnectorConfig = z.object({
  /** Region to inventory. This is an AWS region id, not an API host. */
  region: z.string().regex(AWS_REGION_RE, 'must be an AWS region identifier'),
  /** Optional expected account; mismatch fails closed so we do not persist the wrong tenant. */
  accountId: z.string().regex(/^\d{12}$/).optional(),
  /** Optional allowlist of resource types; omit to inventory the default set. */
  resourceTypes: z.array(AwsResourceType).optional(),
});
export type AwsConnectorConfig = z.infer<typeof AwsConnectorConfig>;

export const AWS_PER_PAGE = 100;
export const AWS_MAX_PAGES = 20;

const DEFAULT_RESOURCE_TYPES: AwsResourceType[] = [
  'ec2_instance',
  's3_bucket',
  'security_group',
  'elastic_ip',
];

export interface AwsInstance {
  instanceId: string;
  state?: string;
  publicIp?: string;
  privateIp?: string;
  name?: string;
}

export interface AwsSecurityGroup {
  groupId: string;
  groupName?: string;
  internetOpen: boolean;
}

export interface AwsElasticIp {
  publicIp: string;
  allocationId?: string;
  instanceId?: string;
}

export interface AwsBucket {
  name: string;
  creationDate?: string;
}

export function instanceToAsset(
  accountId: string,
  region: string,
  instance: AwsInstance,
): UpsertAssetRequest {
  return {
    kind: 'cloud_resource',
    externalKey: `aws:${accountId}:ec2:${region}:${instance.instanceId}`,
    name: instance.name || instance.instanceId,
    source: 'aws',
    exposure: instance.publicIp ? 'internet_facing' : 'internal',
    attributes: {
      accountId,
      region,
      resourceType: 'ec2_instance',
      arn: `arn:aws:ec2:${region}:${accountId}:instance/${instance.instanceId}`,
      instanceId: instance.instanceId,
      state: instance.state ?? null,
      publicIp: instance.publicIp ?? null,
      privateIp: instance.privateIp ?? null,
    },
  };
}

export function securityGroupToAsset(
  accountId: string,
  region: string,
  group: AwsSecurityGroup,
): UpsertAssetRequest {
  return {
    kind: 'cloud_resource',
    externalKey: `aws:${accountId}:sg:${region}:${group.groupId}`,
    name: group.groupName || group.groupId,
    source: 'aws',
    exposure: group.internetOpen ? 'internet_facing' : 'internal',
    attributes: {
      accountId,
      region,
      resourceType: 'security_group',
      arn: `arn:aws:ec2:${region}:${accountId}:security-group/${group.groupId}`,
      groupId: group.groupId,
      groupName: group.groupName ?? null,
    },
  };
}

export function elasticIpToAsset(
  accountId: string,
  region: string,
  address: AwsElasticIp,
): UpsertAssetRequest {
  return {
    kind: 'cloud_resource',
    externalKey: `aws:${accountId}:eip:${region}:${address.allocationId || address.publicIp}`,
    name: address.publicIp,
    source: 'aws',
    exposure: 'internet_facing',
    attributes: {
      accountId,
      region,
      resourceType: 'elastic_ip',
      publicIp: address.publicIp,
      allocationId: address.allocationId ?? null,
      instanceId: address.instanceId ?? null,
    },
  };
}

export function bucketToAsset(accountId: string, region: string, bucket: AwsBucket): UpsertAssetRequest {
  return {
    kind: 'cloud_resource',
    externalKey: `aws:${accountId}:s3:${bucket.name}`,
    name: bucket.name,
    source: 'aws',
    // Bucket policy / ACL is CSPM. Inventory does not claim exposure.
    exposure: 'unknown',
    attributes: {
      accountId,
      region,
      resourceType: 's3_bucket',
      arn: `arn:aws:s3:::${bucket.name}`,
      creationDate: bucket.creationDate ?? null,
    },
  };
}

export function parseCallerAccount(xml: string): string {
  const account = xmlTag(xml, 'Account');
  if (!account || !/^\d{12}$/.test(account)) {
    throw new Error('AWS STS GetCallerIdentity did not return a 12-digit account id');
  }
  return account;
}

export function parseEc2Instances(xml: string): AwsInstance[] {
  const instances: AwsInstance[] = [];
  for (const set of extractTagBlocks(xml, 'instancesSet')) {
    for (const item of extractTagBlocks(set, 'item')) {
      const instanceId = xmlTag(item, 'instanceId');
      if (!instanceId) continue;
      instances.push({
        instanceId,
        state: xmlTag(item, 'name'),
        publicIp: xmlTag(item, 'ipAddress') || xmlTag(item, 'publicIpAddress'),
        privateIp: xmlTag(item, 'privateIpAddress'),
        name: instanceName(item),
      });
    }
  }
  return instances;
}

function instanceName(itemXml: string): string | undefined {
  for (const tag of extractTagBlocks(itemXml, 'item')) {
    if (xmlTag(tag, 'key') === 'Name') return xmlTag(tag, 'value');
  }
  return undefined;
}

export function parseSecurityGroups(xml: string): AwsSecurityGroup[] {
  const groups: AwsSecurityGroup[] = [];
  const body = xmlTag(xml, 'securityGroupInfo') ?? xml;
  for (const item of extractTagBlocks(body, 'item')) {
    const groupId = xmlTag(item, 'groupId');
    if (!groupId) continue;
    // Ingress only — egress 0.0.0.0/0 is the default and is not exposure.
    const ingress = xmlTag(item, 'ipPermissions') ?? '';
    const cidrs = xmlTags(ingress, 'cidrIp');
    const ipv6 = xmlTags(ingress, 'cidrIpv6');
    groups.push({
      groupId,
      groupName: xmlTag(item, 'groupName'),
      internetOpen: cidrs.includes('0.0.0.0/0') || ipv6.includes('::/0'),
    });
  }
  return groups;
}

export function parseElasticIps(xml: string): AwsElasticIp[] {
  const addresses: AwsElasticIp[] = [];
  for (const item of extractTagBlocks(xml, 'item')) {
    const publicIp = xmlTag(item, 'publicIp');
    if (!publicIp) continue;
    addresses.push({
      publicIp,
      allocationId: xmlTag(item, 'allocationId'),
      instanceId: xmlTag(item, 'instanceId'),
    });
  }
  return addresses;
}

export function parseBuckets(xml: string): AwsBucket[] {
  return extractTagBlocks(xml, 'Bucket').map((block) => ({
    name: xmlTag(block, 'Name') ?? '',
    creationDate: xmlTag(block, 'CreationDate'),
  })).filter((b) => b.name.length > 0);
}

/**
 * Cloud-resource inventory via AWS APIs. Same persistence path as GitHub/GitLab:
 * discover → UpsertAssetRequest → scheduler upsert + archiveStale scoped per
 * integrationId.
 *
 * Hosts are hardcoded to allowlisted `*.amazonaws.com`. Tenant config/body/query
 * cannot set a custom endpoint. Credentials are platform-operated `env:AWS_*`
 * and fail closed when missing — there is no public-listing fallback.
 *
 * This connector always full-scans. `ctx.orgId` is unused (tenancy is applied
 * by the scheduler on persist) and `ctx.since` is unused — AWS list APIs do
 * not offer a reliable incremental window for this inventory.
 */
@Injectable()
export class AwsConnector implements AssetConnector {
  readonly provider = 'aws';
  readonly assetKinds = ['cloud_resource'];
  private readonly log = rootLogger.child({ component: 'aws-connector' });

  async *discover(ctx: DiscoveryContext): AsyncIterable<UpsertAssetRequest> {
    refuseTenantWritableEndpoint(ctx.config);
    const config = AwsConnectorConfig.parse(ctx.config);
    const creds = requireAwsCredentials(ctx.credentialRef);

    const accountId = await this.callerAccount(config.region, creds);
    if (config.accountId && config.accountId !== accountId) {
      throw new Error(
        `AWS account ${accountId} does not match configured accountId ${config.accountId} — refusing to inventory`,
      );
    }

    const allow = new Set(config.resourceTypes?.length ? config.resourceTypes : DEFAULT_RESOURCE_TYPES);
    let seen = 0;

    if (allow.has('ec2_instance')) {
      for await (const asset of this.listInstances(config.region, creds, accountId)) {
        seen += 1;
        yield asset;
      }
    }
    if (allow.has('security_group')) {
      for await (const asset of this.listSecurityGroups(config.region, creds, accountId)) {
        seen += 1;
        yield asset;
      }
    }
    if (allow.has('elastic_ip')) {
      for (const asset of await this.listElasticIps(config.region, creds, accountId)) {
        seen += 1;
        yield asset;
      }
    }
    if (allow.has('s3_bucket')) {
      for (const asset of await this.listBuckets(config.region, creds, accountId)) {
        seen += 1;
        yield asset;
      }
    }

    this.log.info({ region: config.region, accountId, resources: seen }, 'aws discovery complete');
  }

  private async callerAccount(region: string, creds: AwsCredentials): Promise<string> {
    const xml = await this.query('sts', region, creds, {
      Action: 'GetCallerIdentity',
      Version: '2011-06-15',
    });
    return parseCallerAccount(xml);
  }

  private async *listInstances(
    region: string,
    creds: AwsCredentials,
    accountId: string,
  ): AsyncIterable<UpsertAssetRequest> {
    yield* this.pagedQuery(
      'ec2',
      region,
      creds,
      { Action: 'DescribeInstances', Version: '2016-11-15' },
      (xml) => parseEc2Instances(xml).map((i) => instanceToAsset(accountId, region, i)),
      'instances',
    );
  }

  private async *listSecurityGroups(
    region: string,
    creds: AwsCredentials,
    accountId: string,
  ): AsyncIterable<UpsertAssetRequest> {
    yield* this.pagedQuery(
      'ec2',
      region,
      creds,
      { Action: 'DescribeSecurityGroups', Version: '2016-11-15' },
      (xml) => parseSecurityGroups(xml).map((g) => securityGroupToAsset(accountId, region, g)),
      'security groups',
    );
  }

  private async listElasticIps(
    region: string,
    creds: AwsCredentials,
    accountId: string,
  ): Promise<UpsertAssetRequest[]> {
    const xml = await this.query('ec2', region, creds, {
      Action: 'DescribeAddresses',
      Version: '2016-11-15',
    });
    return parseElasticIps(xml).map((a) => elasticIpToAsset(accountId, region, a));
  }

  private async listBuckets(
    region: string,
    creds: AwsCredentials,
    accountId: string,
  ): Promise<UpsertAssetRequest[]> {
    const url = allowlistedAwsUrl('https://s3.amazonaws.com/');
    const signed = signAwsRequest({
      method: 'GET',
      url,
      region: 'us-east-1',
      service: 's3',
      credentials: creds,
    });
    const xml = await this.send(signed, 's3', 'ListBuckets');
    if (xmlIsTruncated(xml) || xmlNextToken(xml)) {
      this.failTruncated('S3 buckets');
    }
    return parseBuckets(xml).map((b) => bucketToAsset(accountId, region, b));
  }

  private async *pagedQuery(
    service: AwsService,
    region: string,
    creds: AwsCredentials,
    params: Record<string, string>,
    mapPage: (xml: string) => UpsertAssetRequest[],
    label: string,
  ): AsyncIterable<UpsertAssetRequest> {
    let token: string | undefined;
    for (let page = 1; page <= AWS_MAX_PAGES; page++) {
      const xml = await this.query(service, region, creds, {
        ...params,
        MaxResults: String(AWS_PER_PAGE),
        ...(token ? { NextToken: token } : {}),
      });
      const assets = mapPage(xml);
      for (const asset of assets) yield asset;
      token = xmlNextToken(xml);
      // AWS is done when NextToken is absent. A full page without a token is
      // complete — do not re-query the same page. A leftover NextToken at the
      // cap is truncated; do not archiveStale on a partial listing.
      if (!token) break;
      if (page === AWS_MAX_PAGES) this.failTruncated(label);
    }
  }

  private failTruncated(label: string): never {
    this.log.error(
      { pages: AWS_MAX_PAGES, perPage: AWS_PER_PAGE, label },
      'aws listing truncated at page cap',
    );
    throw new Error(
      `AWS listing truncated at ${AWS_MAX_PAGES * AWS_PER_PAGE} ${label} (page cap ${AWS_MAX_PAGES}); refusing to archive unseen assets`,
    );
  }

  private async query(
    service: AwsService,
    region: string,
    creds: AwsCredentials,
    params: Record<string, string>,
  ): Promise<string> {
    const url = awsServiceUrl(service, region);
    const signingRegion = service === 's3' ? 'us-east-1' : region;
    const body = new URLSearchParams(params).toString();
    const signed = signAwsRequest({
      method: 'POST',
      url,
      region: signingRegion,
      service,
      credentials: creds,
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body,
    });
    return this.send(signed, service, params.Action ?? 'unknown');
  }

  private async send(
    signed: { url: string; method: 'GET' | 'POST'; headers: Record<string, string>; body?: string },
    service: string,
    action: string,
  ): Promise<string> {
    // Belt: never send keys off the allowlist even if a caller built `signed`.
    allowlistedAwsUrl(signed.url);
    const res = await fetch(signed.url, {
      method: signed.method,
      headers: signed.headers,
      body: signed.method === 'POST' ? signed.body : undefined,
      signal: AbortSignal.timeout(20_000),
    });
    if (!res.ok) {
      throw new Error(`AWS ${service} API returned ${res.status} for ${action}`);
    }
    return res.text();
  }
}
