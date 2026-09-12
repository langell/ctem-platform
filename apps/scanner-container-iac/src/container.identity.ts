/**
 * Container image identity. Discovery keys `container_image` assets as:
 *   `ghcr:owner/name@sha256:<64 hex>`  — GHCR content digest
 *   `ecr:{accountId}/{repositoryName}@sha256:<64 hex>` — ECR content digest
 * Never a mutable tag. Region is an AWS region id on the asset / integration
 * config, not a host, and is not encoded in the ECR externalKey.
 */

import { AWS_REGION_RE } from './aws.egress';
import { AWS_ACCOUNT_RE, ContainerEgressError, refuseTenantWritableRegistry } from './container.egress';

export const SHA256_DIGEST_RE = /^sha256:[a-f0-9]{64}$/i;
export const GHCR_EXTERNAL_KEY_RE = /^ghcr:([^/@]+)\/(.+)@(sha256:[a-f0-9]{64})$/i;
export const ECR_EXTERNAL_KEY_RE = /^ecr:(\d{12})\/(.+)@(sha256:[a-f0-9]{64})$/i;
export { AWS_ACCOUNT_RE };

export class ContainerIdentityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ContainerIdentityError';
  }
}

export interface GhcrImageRef {
  kind?: 'ghcr';
  owner: string;
  name: string;
  digest: string;
}

export interface EcrImageRef {
  kind: 'ecr';
  accountId: string;
  repositoryName: string;
  digest: string;
  region: string;
}

export type ContainerImageRef = (GhcrImageRef & { kind: 'ghcr' }) | EcrImageRef;

function failIdentity(message: string): never {
  throw new ContainerIdentityError(message);
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

/**
 * Parse `externalKey` / attributes for `ghcr:owner/name@sha256:<digest>`.
 * Refuses tags, other registries, and tenant-writable registry hosts before
 * any network connect.
 */
export function parseGhcrImageRef(
  target: Record<string, unknown>,
  options: Record<string, unknown> = {},
): GhcrImageRef {
  refuseTenantWritableRegistry(options);
  refuseTenantWritableRegistry(target);

  const key = typeof target.externalKey === 'string' ? target.externalKey.trim() : '';
  let fromKey: GhcrImageRef | undefined;
  if (key) {
    const match = GHCR_EXTERNAL_KEY_RE.exec(key);
    if (!match) {
      failIdentity(
        `Refusing non-digest or malformed container identity '${key}' — expected ghcr:owner/name@sha256:<64 hex>`,
      );
    }
    fromKey = { owner: match[1]!, name: match[2]!, digest: match[3]!.toLowerCase() };
  }

  const attrs = asRecord(target.attributes);
  const ownerAttr = stringAttr(target.owner) ?? stringAttr(attrs.owner);
  const nameAttr = stringAttr(target.package) ?? stringAttr(attrs.package);
  const digestAttr = stringAttr(target.digest) ?? stringAttr(attrs.digest);

  if (fromKey) {
    if (ownerAttr && ownerAttr !== fromKey.owner) {
      failIdentity('Container asset owner does not match ghcr: identity — refusing pull');
    }
    if (nameAttr && nameAttr !== fromKey.name) {
      failIdentity('Container asset package does not match ghcr: identity — refusing pull');
    }
    if (digestAttr) {
      if (!SHA256_DIGEST_RE.test(digestAttr)) {
        failIdentity(`Refusing non-digest container attribute digest '${digestAttr}'`);
      }
      if (digestAttr.toLowerCase() !== fromKey.digest) {
        failIdentity('Container asset digest does not match ghcr: identity — refusing pull');
      }
    }
    return fromKey;
  }

  if (ownerAttr && nameAttr && digestAttr && SHA256_DIGEST_RE.test(digestAttr)) {
    return { owner: ownerAttr, name: nameAttr, digest: digestAttr.toLowerCase() };
  }

  failIdentity(
    'Refusing container_image without ghcr:owner/name@sha256:<digest> identity — no tag fallback, no other registry',
  );
}

/**
 * Parse `externalKey` / attributes for `ecr:{account}/{repo}@sha256:<digest>`.
 * Region is an id from asset attributes or integration config — never a host.
 */
export function parseEcrImageRef(
  target: Record<string, unknown>,
  options: Record<string, unknown> = {},
): EcrImageRef {
  refuseTenantWritableRegistry(options);
  refuseTenantWritableRegistry(target);

  const key = typeof target.externalKey === 'string' ? target.externalKey.trim() : '';
  let fromKey: { accountId: string; repositoryName: string; digest: string } | undefined;
  if (key) {
    const match = ECR_EXTERNAL_KEY_RE.exec(key);
    if (!match) {
      failIdentity(
        `Refusing non-digest or malformed container identity '${key}' — expected ecr:{accountId}/{repositoryName}@sha256:<64 hex>`,
      );
    }
    fromKey = {
      accountId: match[1]!,
      repositoryName: match[2]!,
      digest: match[3]!.toLowerCase(),
    };
  }

  const attrs = asRecord(target.attributes);
  const accountAttr = stringAttr(target.accountId) ?? stringAttr(attrs.accountId);
  const repoAttr =
    stringAttr(target.repository) ??
    stringAttr(attrs.repository) ??
    stringAttr(target.repositoryName) ??
    stringAttr(attrs.repositoryName);
  const digestAttr = stringAttr(target.digest) ?? stringAttr(attrs.digest);

  if (fromKey) {
    if (accountAttr && accountAttr !== fromKey.accountId) {
      failIdentity('Container asset accountId does not match ecr: identity — refusing pull');
    }
    if (repoAttr && repoAttr !== fromKey.repositoryName) {
      failIdentity('Container asset repository does not match ecr: identity — refusing pull');
    }
    if (digestAttr) {
      if (!SHA256_DIGEST_RE.test(digestAttr)) {
        failIdentity(`Refusing non-digest container attribute digest '${digestAttr}'`);
      }
      if (digestAttr.toLowerCase() !== fromKey.digest) {
        failIdentity('Container asset digest does not match ecr: identity — refusing pull');
      }
    }
    return {
      kind: 'ecr',
      ...fromKey,
      region: resolveEcrRegion(target, options),
    };
  }

  if (
    accountAttr &&
    AWS_ACCOUNT_RE.test(accountAttr) &&
    repoAttr &&
    digestAttr &&
    SHA256_DIGEST_RE.test(digestAttr)
  ) {
    return {
      kind: 'ecr',
      accountId: accountAttr,
      repositoryName: repoAttr,
      digest: digestAttr.toLowerCase(),
      region: resolveEcrRegion(target, options),
    };
  }

  failIdentity(
    'Refusing container_image without ecr:{accountId}/{repositoryName}@sha256:<digest> identity — no tag fallback, no other registry',
  );
}

/**
 * Accept GHCR or ECR digest identities. Other registries (Docker Hub, GCR,
 * ACR, Quay) are refused. Pull is by digest only.
 */
export function parseContainerImageRef(
  target: Record<string, unknown>,
  options: Record<string, unknown> = {},
): ContainerImageRef {
  refuseTenantWritableRegistry(options);
  refuseTenantWritableRegistry(target);

  const key = typeof target.externalKey === 'string' ? target.externalKey.trim() : '';
  if (key) {
    if (GHCR_EXTERNAL_KEY_RE.test(key)) {
      return { kind: 'ghcr', ...parseGhcrImageRef(target, options) };
    }
    if (ECR_EXTERNAL_KEY_RE.test(key)) {
      return parseEcrImageRef(target, options);
    }
    failIdentity(
      `Refusing non-digest or malformed container identity '${key}' — expected ghcr:owner/name@sha256:<64 hex> or ecr:{accountId}/{repositoryName}@sha256:<64 hex>`,
    );
  }

  const attrs = asRecord(target.attributes);
  const ownerAttr = stringAttr(target.owner) ?? stringAttr(attrs.owner);
  const nameAttr = stringAttr(target.package) ?? stringAttr(attrs.package);
  const digestAttr = stringAttr(target.digest) ?? stringAttr(attrs.digest);
  const accountAttr = stringAttr(target.accountId) ?? stringAttr(attrs.accountId);

  if (ownerAttr && nameAttr && digestAttr && SHA256_DIGEST_RE.test(digestAttr) && !accountAttr) {
    return { kind: 'ghcr', ...parseGhcrImageRef(target, options) };
  }
  if (accountAttr && AWS_ACCOUNT_RE.test(accountAttr)) {
    return parseEcrImageRef(target, options);
  }

  failIdentity(
    'Refusing container_image without ghcr: or ecr: digest identity — no tag fallback, no other registry',
  );
}

function resolveEcrRegion(
  target: Record<string, unknown>,
  options: Record<string, unknown>,
): string {
  const attrs = asRecord(target.attributes);
  const fromTarget = stringAttr(target.region) ?? stringAttr(attrs.region);
  const fromOptions = stringAttr(options.region);
  if (fromTarget && fromOptions && fromTarget !== fromOptions) {
    failIdentity('Container asset region does not match integration region — refusing pull');
  }
  const region = fromTarget ?? fromOptions;
  if (!region) {
    const regions = options.regions;
    if (Array.isArray(regions)) {
      const ids = regions.filter((item): item is string => typeof item === 'string' && item.length > 0);
      if (ids.length === 1) return assertRegionId(ids[0]!);
      if (ids.length > 1) {
        failIdentity('Refusing ECR pull with ambiguous regions — region is an id, pick one');
      }
    }
    failIdentity(
      'Refusing ECR pull without a region id — region comes from asset attributes or integration config, not a registry host',
    );
  }
  return assertRegionId(region);
}

function assertRegionId(region: string): string {
  if (/^https?:\/\//i.test(region.trim())) {
    throw new ContainerEgressError(
      "Refusing tenant-writable container registry endpoint (region) — region is an id, not a host",
    );
  }
  if (!AWS_REGION_RE.test(region)) {
    failIdentity(`Refusing AWS region '${region}' — not a valid AWS region identifier`);
  }
  return region;
}

function stringAttr(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

export function isPrivateContainerImage(target: Record<string, unknown>): boolean {
  if (target.private === true) return true;
  if (target.visibility === 'private') return true;
  const attrs = asRecord(target.attributes);
  if (attrs.private === true) return true;
  if (attrs.visibility === 'private') return true;
  return false;
}

export { ContainerEgressError };
