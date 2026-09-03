import type { MisconfigRule } from './misconfig.rules';
import type { IacKind } from './detect';
import type { HclResource } from './parse/hcl';
import { dockerfileRunsAsRoot, type DockerfileResource } from './parse/dockerfile';

export interface IacMatch {
  rule: MisconfigRule;
  path: string;
  startLine: number;
  address: string;
  snippet: string;
}

export interface EvaluableResource {
  kind: IacKind;
  path: string;
  address: string;
  type: string;
  startLine: number;
  attributes: Record<string, unknown>;
  snippet: string;
}

const PUBLIC_ACLS = new Set(['public-read', 'public-read-write']);
const ALL_USERS = 'http://acs.amazonaws.com/groups/global/AllUsers';

export function evaluableFromHcl(path: string, resource: HclResource, source: string): EvaluableResource {
  return {
    kind: 'terraform',
    path,
    address: resource.address,
    type: resource.type,
    startLine: resource.startLine,
    attributes: resource.attributes,
    snippet: snippetAround(source, resource.startLine),
  };
}

export function evaluableFromCfn(
  path: string,
  logicalId: string,
  type: string,
  properties: Record<string, unknown>,
  startLine: number,
  source: string,
): EvaluableResource {
  return {
    kind: 'cloudformation',
    path,
    address: logicalId,
    type,
    startLine,
    attributes: properties,
    snippet: snippetAround(source, startLine),
  };
}

export function evaluableFromK8s(
  path: string,
  kind: IacKind,
  resourceKind: string,
  name: string,
  attributes: Record<string, unknown>,
  startLine: number,
  source: string,
): EvaluableResource {
  return {
    kind,
    path,
    address: `${resourceKind}/${name || 'unnamed'}`,
    type: resourceKind,
    startLine,
    attributes,
    snippet: snippetAround(source, startLine),
  };
}

export function evaluableFromDockerfile(
  path: string,
  resource: DockerfileResource,
  source: string,
): EvaluableResource {
  return {
    kind: 'dockerfile',
    path,
    address: resource.implicitRoot ? 'USER:root' : `USER:${resource.user}`,
    type: 'Dockerfile',
    startLine: resource.startLine,
    attributes: { user: resource.user, implicitRoot: resource.implicitRoot },
    snippet: snippetAround(source, resource.startLine),
  };
}

export function evaluateResource(resource: EvaluableResource, rules: MisconfigRule[]): IacMatch[] {
  const applicable = rules.filter((rule) => rule.targets.includes(resource.kind));
  const matches: IacMatch[] = [];
  for (const rule of applicable) {
    if (hitsRule(rule.id, resource)) {
      matches.push({
        rule,
        path: resource.path,
        startLine: resource.startLine,
        address: resource.address,
        snippet: resource.snippet,
      });
    }
  }
  return matches;
}

function hitsRule(ruleId: string, resource: EvaluableResource): boolean {
  switch (ruleId) {
    case 'ctem.iac.s3-public':
      return isPublicBucket(resource);
    case 'ctem.iac.sg-open-ssh':
      return isOpenSsh(resource);
    case 'ctem.k8s.privileged-container':
      return isPrivileged(resource);
    case 'ctem.k8s.no-resource-limits':
      return missingLimits(resource);
    case 'ctem.docker.root-user':
      return isRootDockerfile(resource);
    case 'ctem.iac.unencrypted-storage':
      return isUnencrypted(resource);
    default:
      return false;
  }
}

function isPublicBucket(resource: EvaluableResource): boolean {
  if (resource.kind === 'terraform') {
    if (resource.type === 'aws_s3_bucket') {
      const acl = String(resource.attributes.acl ?? '');
      if (PUBLIC_ACLS.has(acl)) return true;
      if (resource.attributes.website !== undefined) return true;
      if (hasAllUsersGrant(resource.attributes.grant)) return true;
    }
    if (resource.type === 'aws_s3_bucket_acl') {
      return PUBLIC_ACLS.has(String(resource.attributes.acl ?? ''));
    }
    if (resource.type === 'aws_s3_bucket_public_access_block') {
      const keys = ['block_public_acls', 'block_public_policy', 'ignore_public_acls', 'restrict_public_buckets'];
      return keys.some((key) => resource.attributes[key] === false);
    }
    if (resource.type === 'aws_s3_bucket_website_configuration') return true;
  }
  if (resource.kind === 'cloudformation' && resource.type === 'AWS::S3::Bucket') {
    const acl = String(resource.attributes.AccessControl ?? '');
    if (PUBLIC_ACLS.has(acl) || acl === 'PublicRead' || acl === 'PublicReadWrite') return true;
    const pab = resource.attributes.PublicAccessBlockConfiguration;
    if (pab && typeof pab === 'object') {
      const rec = pab as Record<string, unknown>;
      return ['BlockPublicAcls', 'BlockPublicPolicy', 'IgnorePublicAcls', 'RestrictPublicBuckets'].some(
        (key) => rec[key] === false,
      );
    }
  }
  return false;
}

function hasAllUsersGrant(grant: unknown): boolean {
  for (const entry of asList(grant)) {
    if (!entry || typeof entry !== 'object') continue;
    const rec = entry as Record<string, unknown>;
    if (String(rec.uri ?? rec.URI ?? '') === ALL_USERS) return true;
  }
  return false;
}

function isOpenSsh(resource: EvaluableResource): boolean {
  if (resource.kind === 'terraform') {
    if (resource.type === 'aws_security_group') {
      return asList(resource.attributes.ingress).some((block) => ingressOpensSsh(block));
    }
    if (resource.type === 'aws_security_group_rule') {
      return String(resource.attributes.type ?? '') === 'ingress' && ingressOpensSsh(resource.attributes);
    }
    if (resource.type === 'aws_vpc_security_group_ingress_rule') {
      return cidrIsOpen(resource.attributes.cidr_ipv4 ?? resource.attributes.cidr_ipv6) && portIncludesSsh(resource.attributes);
    }
  }
  if (resource.kind === 'cloudformation') {
    if (resource.type === 'AWS::EC2::SecurityGroup') {
      return asList(resource.attributes.SecurityGroupIngress).some((block) => cfnIngressOpensSsh(block));
    }
    if (resource.type === 'AWS::EC2::SecurityGroupIngress') {
      return cfnIngressOpensSsh(resource.attributes);
    }
  }
  return false;
}

function ingressOpensSsh(block: unknown): boolean {
  if (!block || typeof block !== 'object') return false;
  const rec = block as Record<string, unknown>;
  const cidrs = [...asList(rec.cidr_blocks), ...asList(rec.ipv6_cidr_blocks), rec.cidr_block, rec.cidr_ipv4];
  if (!cidrs.some(cidrIsOpen)) return false;
  return portIncludesSsh(rec);
}

function cfnIngressOpensSsh(block: unknown): boolean {
  if (!block || typeof block !== 'object') return false;
  const rec = block as Record<string, unknown>;
  if (!cidrIsOpen(rec.CidrIp ?? rec.CidrIpv6)) return false;
  return portIncludesSsh({
    from_port: rec.FromPort,
    to_port: rec.ToPort,
    protocol: rec.IpProtocol,
  });
}

function portIncludesSsh(rec: Record<string, unknown>): boolean {
  const protocol = String(rec.protocol ?? rec.IpProtocol ?? 'tcp').toLowerCase();
  if (protocol !== 'tcp' && protocol !== '-1' && protocol !== '6') return false;
  const from = Number(rec.from_port ?? rec.FromPort ?? 0);
  const to = Number(rec.to_port ?? rec.ToPort ?? from);
  if (Number.isNaN(from) || Number.isNaN(to)) return false;
  return from <= 22 && to >= 22;
}

function cidrIsOpen(value: unknown): boolean {
  return asList(value).some((cidr) => cidr === '0.0.0.0/0' || cidr === '::/0');
}

function isPrivileged(resource: EvaluableResource): boolean {
  if (resource.kind !== 'kubernetes' && resource.kind !== 'helm') return false;
  const spec = podSpec(resource.attributes);
  if (!spec) return false;
  if (securityContextPrivileged(spec.securityContext)) return true;
  return k8sContainers(spec).some((c) => securityContextPrivileged(c.securityContext));
}

function missingLimits(resource: EvaluableResource): boolean {
  if (resource.kind !== 'kubernetes' && resource.kind !== 'helm') return false;
  const spec = podSpec(resource.attributes);
  if (!spec) return false;
  const containers = k8sContainers(spec);
  if (!containers.length) return false;
  return containers.some((c) => {
    const limits = (c.resources as Record<string, unknown> | undefined)?.limits;
    if (!limits || typeof limits !== 'object') return true;
    const rec = limits as Record<string, unknown>;
    return rec.cpu === undefined && rec.memory === undefined;
  });
}

function podSpec(attributes: Record<string, unknown>): Record<string, unknown> | null {
  const spec = attributes.spec;
  if (!spec || typeof spec !== 'object') return null;
  const rec = spec as Record<string, unknown>;
  const template = rec.template;
  if (template && typeof template === 'object') {
    const tspec = (template as Record<string, unknown>).spec;
    if (tspec && typeof tspec === 'object') return tspec as Record<string, unknown>;
  }
  return rec;
}

function k8sContainers(spec: Record<string, unknown>): Array<Record<string, unknown>> {
  return asList(spec.containers).filter((c): c is Record<string, unknown> => !!c && typeof c === 'object');
}

function securityContextPrivileged(value: unknown): boolean {
  if (!value || typeof value !== 'object') return false;
  return (value as Record<string, unknown>).privileged === true;
}

function isRootDockerfile(resource: EvaluableResource): boolean {
  if (resource.kind !== 'dockerfile') return false;
  return dockerfileRunsAsRoot({
    user: (resource.attributes.user as string | null) ?? null,
    implicitRoot: Boolean(resource.attributes.implicitRoot),
    startLine: resource.startLine,
  });
}

function isUnencrypted(resource: EvaluableResource): boolean {
  if (resource.kind === 'terraform') {
    if (resource.type === 'aws_ebs_volume') return resource.attributes.encrypted !== true;
    if (resource.type === 'aws_db_instance' || resource.type === 'aws_rds_cluster') {
      return resource.attributes.storage_encrypted !== true;
    }
    if (resource.type === 'aws_instance') {
      return [...asList(resource.attributes.root_block_device), ...asList(resource.attributes.ebs_block_device)].some(
        (block) => block && typeof block === 'object' && (block as Record<string, unknown>).encrypted === false,
      );
    }
    if (resource.type === 'aws_s3_bucket') {
      return resource.attributes.server_side_encryption_configuration === undefined;
    }
  }
  if (resource.kind === 'cloudformation') {
    if (resource.type === 'AWS::EC2::Volume') return resource.attributes.Encrypted !== true;
    if (resource.type === 'AWS::RDS::DBInstance' || resource.type === 'AWS::RDS::DBCluster') {
      return resource.attributes.StorageEncrypted !== true;
    }
    if (resource.type === 'AWS::S3::Bucket') return resource.attributes.BucketEncryption === undefined;
  }
  return false;
}

function asList(value: unknown): unknown[] {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

export function snippetAround(source: string, startLine: number): string {
  const lines = source.split('\n');
  const idx = Math.max(0, startLine - 1);
  return (lines[idx] ?? '').trim().slice(0, 240);
}
