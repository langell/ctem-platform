import type { RawFinding } from '@ctem/contracts';
import type { AwsCredentials, AzureCredentials, GcpCredentials } from './credentials';
import {
  allowlistedAwsUrl,
  awsS3BucketUrl,
  awsServiceUrl,
  assertAwsSecurityGroupId,
  refuseTenantWritableEndpoint as refuseAwsEndpoint,
} from './aws.egress';
import { signAwsRequest } from './aws.sigv4';
import { xmlIsTruncated, xmlNextToken, xmlTag, xmlTags, extractTagBlocks } from './aws.xml';
import {
  allowlistedGcpUrl,
  gcpFirewallUrl,
  gcpStorageBucketIamUrl,
  gcpStorageBucketUrl,
  refuseTenantWritableEndpoint as refuseGcpEndpoint,
} from './gcp.egress';
import { exchangeGcpAccessToken } from './gcp.jwt';
import {
  AZURE_NETWORK_API_VERSION,
  AZURE_STORAGE_API_VERSION,
  allowlistedAzureArmUrl,
  azureArmResourceUrl,
  refuseTenantWritableEndpoint as refuseAzureEndpoint,
} from './azure.egress';
import { exchangeAzureAccessToken } from './azure.token';
import {
  CspmScanError,
  type CloudFetch,
  type RecordedCloudCall,
  guardedFetch,
  walkPages,
} from './cloud.fetch';
import { POSTURE_RULES } from './posture.rules';

export type CspmProvider = 'aws' | 'gcp' | 'azure';

export interface EvaluatedFinding {
  ruleId: string;
  title: string;
  severity: RawFinding['severity'];
  remediation: string;
  resource: string;
  evidence: Record<string, unknown>;
}

const ALL_USERS_URI = 'http://acs.amazonaws.com/groups/global/AllUsers';
const AUTH_USERS_URI = 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers';
const PUBLIC_ACL_PERMS = new Set(['READ', 'WRITE', 'READ_ACP', 'WRITE_ACP', 'FULL_CONTROL']);

export class PostureEvaluator {
  readonly calls: RecordedCloudCall[] = [];
  private readonly fetchImpl: CloudFetch;

  constructor(fetchImpl: CloudFetch = globalThis.fetch.bind(globalThis)) {
    this.fetchImpl = guardedFetch(fetchImpl, this.calls);
  }

  refuseTenantEndpoints(config: Record<string, unknown>): void {
    refuseAwsEndpoint(config);
    refuseGcpEndpoint(config);
    refuseAzureEndpoint(config);
  }

  async evaluate(args: {
    provider: CspmProvider;
    resourceType: string;
    target: Record<string, unknown>;
    credentialRef: string | null;
    requireAws: (ref: string | null) => AwsCredentials;
    requireGcp: (ref: string | null) => GcpCredentials;
    requireAzure: (ref: string | null) => AzureCredentials;
  }): Promise<EvaluatedFinding[]> {
    switch (args.provider) {
      case 'aws':
        return this.evaluateAws(args.resourceType, args.target, args.requireAws(args.credentialRef));
      case 'gcp':
        return this.evaluateGcp(args.resourceType, args.target, args.requireGcp(args.credentialRef));
      case 'azure':
        return this.evaluateAzure(args.resourceType, args.target, args.requireAzure(args.credentialRef));
    }
  }

  private async evaluateAws(
    resourceType: string,
    target: Record<string, unknown>,
    creds: AwsCredentials,
  ): Promise<EvaluatedFinding[]> {
    const region = optionalString(target, 'region') ?? 'us-east-1';
    if (resourceType === 's3_bucket') {
      const bucket = optionalString(target, 'name') ?? bucketFromExternalKey(target, 'aws');
      const arn = optionalString(target, 'arn') ?? `arn:aws:s3:::${bucket}`;
      return this.evaluateAwsBucket(region, bucket, arn, creds);
    }
    if (resourceType === 'security_group') {
      const groupId = optionalString(target, 'groupId') ?? lastExternalSegment(target);
      const arn =
        optionalString(target, 'arn') ||
        `arn:aws:ec2:${region}:${optionalString(target, 'accountId') ?? 'unknown'}:security-group/${groupId}`;
      return this.evaluateAwsSg(region, groupId, arn, creds);
    }
    await this.awsCallerIdentity(region, creds);
    return [];
  }

  private async evaluateGcp(
    resourceType: string,
    target: Record<string, unknown>,
    creds: GcpCredentials,
  ): Promise<EvaluatedFinding[]> {
    const token = await exchangeGcpAccessToken(creds, this.fetchImpl);
    const projectId = optionalString(target, 'projectId');
    if (resourceType === 'gcs_bucket') {
      const bucket = optionalString(target, 'name') ?? bucketFromExternalKey(target, 'gcp');
      return this.evaluateGcsBucket(bucket, token);
    }
    if (resourceType === 'firewall') {
      if (!projectId) {
        throw new CspmScanError('Cloud resource is missing projectId — refusing empty success');
      }
      const name = optionalString(target, 'name') ?? lastExternalSegment(target);
      return this.evaluateGcpFirewall(projectId, name, token);
    }
    return [];
  }

  private async evaluateAzure(
    resourceType: string,
    target: Record<string, unknown>,
    creds: AzureCredentials,
  ): Promise<EvaluatedFinding[]> {
    const token = await exchangeAzureAccessToken(creds, this.fetchImpl);
    const subscriptionId = optionalString(target, 'subscriptionId');
    const resourceGroup = optionalString(target, 'resourceGroup');
    const name = optionalString(target, 'name') ?? lastExternalSegment(target);
    if ((resourceType === 'storage_account' || resourceType === 'nsg') && (!subscriptionId || !resourceGroup)) {
      throw new CspmScanError(
        'Cloud resource is missing subscriptionId/resourceGroup — refusing empty success',
      );
    }
    if (resourceType === 'storage_account') {
      return this.evaluateAzureStorage(subscriptionId!, resourceGroup!, name, token);
    }
    if (resourceType === 'nsg') {
      return this.evaluateAzureNsg(subscriptionId!, resourceGroup!, name, token);
    }
    return [];
  }

  private async evaluateAwsBucket(
    region: string,
    bucket: string,
    resource: string,
    creds: AwsCredentials,
  ): Promise<EvaluatedFinding[]> {
    const pab = await this.s3Xml(region, bucket, { publicAccessBlock: '' }, creds, {
      allowMissing: ['NoSuchPublicAccessBlockConfiguration', '404'],
    });
    const fullyBlocked =
      pab !== null &&
      xmlTag(pab, 'BlockPublicAcls')?.toLowerCase() === 'true' &&
      xmlTag(pab, 'BlockPublicPolicy')?.toLowerCase() === 'true' &&
      xmlTag(pab, 'IgnorePublicAcls')?.toLowerCase() === 'true' &&
      xmlTag(pab, 'RestrictPublicBuckets')?.toLowerCase() === 'true';
    if (fullyBlocked) return [];

    const policyStatus = await this.s3Xml(region, bucket, { policyStatus: '' }, creds, {
      allowMissing: ['NoSuchBucketPolicy', '404'],
    });
    const policyPublic = policyStatus !== null && xmlTag(policyStatus, 'IsPublic')?.toLowerCase() === 'true';

    const aclPublic = await this.s3AclIsPublic(region, bucket, creds);

    if (!policyPublic && !aclPublic) return [];
    return [
      finding(POSTURE_RULES.publicBucket, resource, {
        policyPublic,
        aclPublic,
        publicAccessBlock: pab,
      }),
    ];
  }

  private async s3AclIsPublic(
    region: string,
    bucket: string,
    creds: AwsCredentials,
  ): Promise<boolean> {
    let publicGrant = false;
    let sawAcl = false;
    await walkPages({
      label: 'S3 ACL',
      fetchPage: (marker) =>
        this.s3Xml(
          region,
          bucket,
          marker ? { acl: '', marker } : { acl: '' },
          creds,
          { allowMissing: ['AccessControlListNotSupported', '400'] },
        ).then((xml) => xml ?? ''),
      nextToken: (xml) => (xml ? xmlNextToken(xml) : undefined),
      isTruncated: (xml) => (xml ? xmlIsTruncated(xml) : false),
      onPage: (xml) => {
        if (!xml) return;
        sawAcl = true;
        if (aclGrantsPublic(xml)) publicGrant = true;
      },
    });
    return sawAcl && publicGrant;
  }

  private async evaluateAwsSg(
    region: string,
    groupId: string,
    resource: string,
    creds: AwsCredentials,
  ): Promise<EvaluatedFinding[]> {
    const id = assertAwsSecurityGroupId(groupId);
    let internetOpen = false;
    let cidrs: string[] = [];
    await walkPages({
      label: 'security groups',
      fetchPage: (token) =>
        this.awsQuery('ec2', region, creds, {
          Action: 'DescribeSecurityGroups',
          Version: '2016-11-15',
          'GroupId.1': id,
          ...(token ? { NextToken: token } : {}),
        }),
      nextToken: xmlNextToken,
      isTruncated: xmlIsTruncated,
      onPage: (xml) => {
        const parsed = parseSgInternetOpen(xml);
        if (parsed.open) internetOpen = true;
        cidrs = [...cidrs, ...parsed.cidrs];
      },
    });
    if (!internetOpen) return [];
    return [
      finding(POSTURE_RULES.openSg, resource, {
        groupId: id,
        internetCidrs: [...new Set(cidrs)],
      }),
    ];
  }

  private async evaluateGcsBucket(bucket: string, token: string): Promise<EvaluatedFinding[]> {
    const members: string[] = [];
    await walkPages({
      label: 'GCS IAM',
      fetchPage: (pageToken) => this.gcpJson(gcpStorageBucketIamUrl(bucket, pageToken), token, 'GCS IAM'),
      nextToken: jsonNextPageToken,
      onPage: (json) => {
        members.push(...iamPublicMembers(json));
      },
    });
    const meta = await this.gcpJson(gcpStorageBucketUrl(bucket, { projection: 'full' }), token, 'GCS bucket');
    const prevention = iamPublicAccessPrevention(meta);
    const publicMembers = [...new Set(members)];
    if (prevention === 'enforced' && publicMembers.length === 0) return [];
    if (publicMembers.length === 0) return [];
    return [
      finding(POSTURE_RULES.publicBucket, `gcp:gcs:${bucket}`, {
        members: publicMembers,
        publicAccessPrevention: prevention,
      }),
    ];
  }

  private async evaluateGcpFirewall(
    projectId: string,
    name: string,
    token: string,
  ): Promise<EvaluatedFinding[]> {
    const json = await this.gcpJson(gcpFirewallUrl(projectId, name), token, 'firewall');
    if (!gcpFirewallInternetOpen(json)) return [];
    return [
      finding(POSTURE_RULES.openSg, `gcp:${projectId}:fw:${name}`, {
        sourceRanges: jsonSourceRanges(json),
        direction: asString((json as { direction?: unknown }).direction) ?? 'INGRESS',
      }),
    ];
  }

  private async evaluateAzureStorage(
    subscriptionId: string,
    resourceGroup: string,
    name: string,
    token: string,
  ): Promise<EvaluatedFinding[]> {
    const url = azureArmResourceUrl(
      subscriptionId,
      resourceGroup,
      '/providers/Microsoft.Storage/storageAccounts',
      name,
      AZURE_STORAGE_API_VERSION,
    );
    const json = await this.azureJson(url, token, 'storage account');
    const props =
      json && typeof json === 'object' && (json as { properties?: unknown }).properties &&
      typeof (json as { properties: unknown }).properties === 'object'
        ? ((json as { properties: Record<string, unknown> }).properties)
        : {};
    const allowBlobPublicAccess = props.allowBlobPublicAccess === true;
    if (!allowBlobPublicAccess) return [];
    return [
      finding(POSTURE_RULES.publicBucket, `azure:${subscriptionId}:sa:${resourceGroup}:${name}`, {
        allowBlobPublicAccess,
      }),
    ];
  }

  private async evaluateAzureNsg(
    subscriptionId: string,
    resourceGroup: string,
    name: string,
    token: string,
  ): Promise<EvaluatedFinding[]> {
    const url = azureArmResourceUrl(
      subscriptionId,
      resourceGroup,
      '/providers/Microsoft.Network/networkSecurityGroups',
      name,
      AZURE_NETWORK_API_VERSION,
    );
    const json = await this.azureJson(url, token, 'NSG');
    const open = azureNsgInternetOpen(json);
    if (!open) return [];
    return [
      finding(POSTURE_RULES.openSg, `azure:${subscriptionId}:nsg:${resourceGroup}:${name}`, {
        internetOpen: true,
      }),
    ];
  }

  private async awsCallerIdentity(region: string, creds: AwsCredentials): Promise<void> {
    await this.awsQuery('sts', region, creds, {
      Action: 'GetCallerIdentity',
      Version: '2011-06-15',
    });
  }

  private async awsQuery(
    service: 'ec2' | 'sts',
    region: string,
    creds: AwsCredentials,
    params: Record<string, string>,
  ): Promise<string> {
    const url = awsServiceUrl(service, region);
    const body = new URLSearchParams(params).toString();
    const signed = signAwsRequest({
      method: 'POST',
      url,
      region,
      service,
      credentials: creds,
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body,
    });
    allowlistedAwsUrl(signed.url);
    const res = await this.fetchImpl(signed.url, {
      method: signed.method,
      headers: signed.headers,
      body: signed.body,
      signal: AbortSignal.timeout(20_000),
    });
    if (!res.ok) {
      throw new CspmScanError(`AWS ${service} API returned ${res.status} for ${params.Action}`);
    }
    return res.text();
  }

  private async s3Xml(
    region: string,
    bucket: string,
    query: Record<string, string>,
    creds: AwsCredentials,
    opts: { allowMissing?: string[] } = {},
  ): Promise<string | null> {
    const url = awsS3BucketUrl(region, bucket, query);
    const signed = signAwsRequest({
      method: 'GET',
      url,
      region: region === 'us-east-1' ? 'us-east-1' : region,
      service: 's3',
      credentials: creds,
    });
    allowlistedAwsUrl(signed.url);
    const res = await this.fetchImpl(signed.url, {
      method: 'GET',
      headers: signed.headers,
      signal: AbortSignal.timeout(20_000),
    });
    if (!res.ok) {
      const text = await res.text();
      if (opts.allowMissing?.some((code) => String(res.status) === code || text.includes(code))) {
        return null;
      }
      throw new CspmScanError(`AWS S3 API returned ${res.status} for ${Object.keys(query).join(',')}`);
    }
    return res.text();
  }

  private async gcpJson(url: string, token: string, label: string): Promise<unknown> {
    allowlistedGcpUrl(url);
    const res = await this.fetchImpl(url, {
      method: 'GET',
      headers: { accept: 'application/json', authorization: `Bearer ${token}` },
      signal: AbortSignal.timeout(20_000),
    });
    if (!res.ok) {
      throw new CspmScanError(`GCP ${label} API returned ${res.status}`);
    }
    return res.json();
  }

  private async azureJson(url: string, token: string, label: string): Promise<unknown> {
    allowlistedAzureArmUrl(url);
    const res = await this.fetchImpl(url, {
      method: 'GET',
      headers: { accept: 'application/json', authorization: `Bearer ${token}` },
      signal: AbortSignal.timeout(20_000),
    });
    if (!res.ok) {
      throw new CspmScanError(`Azure ${label} API returned ${res.status}`);
    }
    return res.json();
  }
}

function finding(
  rule: (typeof POSTURE_RULES)[keyof typeof POSTURE_RULES],
  resource: string,
  evidence: Record<string, unknown>,
): EvaluatedFinding {
  return {
    ruleId: rule.id,
    title: rule.title,
    severity: rule.severity,
    remediation: rule.remediation,
    resource,
    evidence,
  };
}

function optionalString(target: Record<string, unknown>, key: string): string | undefined {
  const value = target[key];
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

function lastExternalSegment(target: Record<string, unknown>): string {
  const key = typeof target.externalKey === 'string' ? target.externalKey : '';
  const parts = key.split(':').filter(Boolean);
  const last = parts.at(-1);
  if (!last) throw new CspmScanError('Cloud resource is missing identity — refusing empty success');
  return last;
}

function bucketFromExternalKey(target: Record<string, unknown>, provider: 'aws' | 'gcp'): string {
  const key = typeof target.externalKey === 'string' ? target.externalKey : '';
  const prefix = provider === 'aws' ? 'aws:' : 'gcp:';
  if (!key.startsWith(prefix)) {
    throw new CspmScanError('Cloud resource identity does not match provider — refusing empty success');
  }
  return lastExternalSegment(target);
}

function aclGrantsPublic(xml: string): boolean {
  for (const grant of extractTagBlocks(xml, 'Grant')) {
    const uri = xmlTag(grant, 'URI') ?? '';
    const perm = (xmlTag(grant, 'Permission') ?? '').toUpperCase();
    if ((uri === ALL_USERS_URI || uri === AUTH_USERS_URI) && PUBLIC_ACL_PERMS.has(perm)) {
      return true;
    }
  }
  return false;
}

function parseSgInternetOpen(xml: string): { open: boolean; cidrs: string[] } {
  const cidrs: string[] = [];
  const body = xmlTag(xml, 'securityGroupInfo') ?? xml;
  for (const item of extractTagBlocks(body, 'item')) {
    const ingress = xmlTag(item, 'ipPermissions') ?? '';
    cidrs.push(...xmlTags(ingress, 'cidrIp'), ...xmlTags(ingress, 'cidrIpv6'));
  }
  const open = cidrs.includes('0.0.0.0/0') || cidrs.includes('::/0');
  return { open, cidrs: cidrs.filter((c) => c === '0.0.0.0/0' || c === '::/0') };
}

function jsonNextPageToken(json: unknown): string | undefined {
  if (!json || typeof json !== 'object') return undefined;
  const token = (json as { nextPageToken?: unknown }).nextPageToken;
  if (typeof token !== 'string') return undefined;
  const trimmed = token.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function iamPublicMembers(json: unknown): string[] {
  if (!json || typeof json !== 'object') return [];
  const bindings = (json as { bindings?: unknown }).bindings;
  if (!Array.isArray(bindings)) return [];
  const publicMembers: string[] = [];
  for (const binding of bindings) {
    if (!binding || typeof binding !== 'object') continue;
    const members = (binding as { members?: unknown }).members;
    if (!Array.isArray(members)) continue;
    for (const member of members) {
      if (member === 'allUsers' || member === 'allAuthenticatedUsers') publicMembers.push(member);
    }
  }
  return publicMembers;
}

function iamPublicAccessPrevention(json: unknown): string | undefined {
  if (!json || typeof json !== 'object') return undefined;
  const iam = (json as { iamConfiguration?: unknown }).iamConfiguration;
  if (!iam || typeof iam !== 'object') return undefined;
  const value = (iam as { publicAccessPrevention?: unknown }).publicAccessPrevention;
  return typeof value === 'string' ? value : undefined;
}

function gcpFirewallInternetOpen(json: unknown): boolean {
  if (!json || typeof json !== 'object') return false;
  const fw = json as { direction?: unknown; sourceRanges?: unknown; allowed?: unknown; disabled?: unknown };
  if (fw.disabled === true) return false;
  const direction = (typeof fw.direction === 'string' ? fw.direction : 'INGRESS').toUpperCase();
  if (direction !== 'INGRESS') return false;
  if (!Array.isArray(fw.allowed) || fw.allowed.length === 0) return false;
  const ranges = Array.isArray(fw.sourceRanges)
    ? fw.sourceRanges.filter((r): r is string => typeof r === 'string')
    : [];
  return ranges.includes('0.0.0.0/0') || ranges.includes('::/0');
}

function jsonSourceRanges(json: unknown): string[] {
  if (!json || typeof json !== 'object') return [];
  const ranges = (json as { sourceRanges?: unknown }).sourceRanges;
  return Array.isArray(ranges) ? ranges.filter((r): r is string => typeof r === 'string') : [];
}

function azureNsgInternetOpen(json: unknown): boolean {
  if (!json || typeof json !== 'object') return false;
  const props = (json as { properties?: unknown }).properties;
  if (!props || typeof props !== 'object') return false;
  const rules = (props as { securityRules?: unknown }).securityRules;
  if (!Array.isArray(rules)) return false;
  for (const rule of rules) {
    if (!rule || typeof rule !== 'object') continue;
    const rp = (rule as { properties?: unknown }).properties;
    if (!rp || typeof rp !== 'object') continue;
    const p = rp as Record<string, unknown>;
    const direction = (typeof p.direction === 'string' ? p.direction : '').toLowerCase();
    const access = (typeof p.access === 'string' ? p.access : '').toLowerCase();
    if (direction === 'inbound' && access === 'allow' && azureInternetSources(p).length) return true;
  }
  return false;
}

function azureInternetSources(props: Record<string, unknown>): string[] {
  const prefixes: string[] = [];
  if (typeof props.sourceAddressPrefix === 'string') prefixes.push(props.sourceAddressPrefix);
  if (Array.isArray(props.sourceAddressPrefixes)) {
    for (const p of props.sourceAddressPrefixes) {
      if (typeof p === 'string') prefixes.push(p);
    }
  }
  return prefixes.filter((p) => {
    const v = p.trim();
    return v === '*' || v === '0.0.0.0/0' || v.toLowerCase() === 'internet';
  });
}

function asString(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}
