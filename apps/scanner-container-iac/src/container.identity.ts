/**
 * Container image identity. Discovery keys `container_image` assets as:
 *   `ghcr:owner/name@sha256:<64 hex>`  — GHCR content digest
 *   `ecr:{accountId}/{repositoryName}@sha256:<64 hex>` — ECR content digest
 *   `gcr:{project}/{location}/{repository}/{image}@sha256:<64 hex>` — Artifact Registry
 *   `acr:{subscriptionId}/{resourceGroup}/{registry}/{repository}@sha256:<64 hex>` — ACR
 * Never a mutable tag. Region / location / project / repository / registry
 * / subscription / resource group are ids, not hosts. The ECR region is not
 * encoded in the externalKey; GCR location and ACR registry are.
 */

import { AWS_REGION_RE } from './aws.egress';
import {
  ACR_REGISTRY_NAME_RE,
  ACR_REPOSITORY_RE,
  AZURE_GUID_RE,
  AZURE_RESOURCE_GROUP_RE,
  AzureEgressError,
  assertAcrLoginServer,
  assertAcrRegistryName,
  assertAcrRepository,
  assertAzureGuid,
  assertAzureResourceGroup,
} from './azure.egress';
import { AWS_ACCOUNT_RE, ContainerEgressError, refuseTenantWritableRegistry } from './container.egress';
import { GCP_LOCATION_ID_RE, GCP_PROJECT_ID_RE, GCR_REPOSITORY_ID_RE } from './gcp.egress';

export const SHA256_DIGEST_RE = /^sha256:[a-f0-9]{64}$/i;
export const GHCR_EXTERNAL_KEY_RE = /^ghcr:([^/@]+)\/(.+)@(sha256:[a-f0-9]{64})$/i;
export const ECR_EXTERNAL_KEY_RE = /^ecr:(\d{12})\/(.+)@(sha256:[a-f0-9]{64})$/i;
export const GCR_EXTERNAL_KEY_RE =
  /^gcr:([^/@]+)\/([^/@]+)\/([^/@]+)\/(.+)@(sha256:[a-f0-9]{64})$/i;
export const ACR_EXTERNAL_KEY_RE =
  /^acr:([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\/([^/@]+)\/([a-z0-9]{5,50})\/(.+)@(sha256:[a-f0-9]{64})$/i;
export { AWS_ACCOUNT_RE, GCP_LOCATION_ID_RE, GCP_PROJECT_ID_RE, GCR_REPOSITORY_ID_RE };
export { AZURE_GUID_RE, ACR_REGISTRY_NAME_RE, ACR_REPOSITORY_RE, AZURE_RESOURCE_GROUP_RE };

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

export interface GcrImageRef {
  kind: 'gcr';
  projectId: string;
  location: string;
  repository: string;
  image: string;
  digest: string;
}

export interface AcrImageRef {
  kind: 'acr';
  subscriptionId: string;
  resourceGroup: string;
  registry: string;
  repository: string;
  digest: string;
}

export type ContainerImageRef =
  | (GhcrImageRef & { kind: 'ghcr' })
  | EcrImageRef
  | GcrImageRef
  | AcrImageRef;

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
 * Parse `externalKey` / attributes for
 * `gcr:{project}/{location}/{repository}/{image}@sha256:<digest>`.
 * Location / project / repository / image are ids — never a pkg.dev host.
 */
export function parseGcrImageRef(
  target: Record<string, unknown>,
  options: Record<string, unknown> = {},
): GcrImageRef {
  refuseTenantWritableRegistry(options);
  refuseTenantWritableRegistry(target);

  const key = typeof target.externalKey === 'string' ? target.externalKey.trim() : '';
  let fromKey:
    | { projectId: string; location: string; repository: string; image: string; digest: string }
    | undefined;
  if (key) {
    const match = GCR_EXTERNAL_KEY_RE.exec(key);
    if (!match) {
      failIdentity(
        `Refusing non-digest or malformed container identity '${key}' — expected gcr:{project}/{location}/{repository}/{image}@sha256:<64 hex>`,
      );
    }
    fromKey = {
      projectId: match[1]!,
      location: match[2]!,
      repository: match[3]!,
      image: match[4]!,
      digest: match[5]!.toLowerCase(),
    };
    assertGcrIdentityParts(fromKey);
  }

  const attrs = asRecord(target.attributes);
  const projectAttr = stringAttr(target.projectId) ?? stringAttr(attrs.projectId);
  const locationAttr = stringAttr(target.location) ?? stringAttr(attrs.location);
  const repoAttr = stringAttr(target.repository) ?? stringAttr(attrs.repository);
  const imageAttr = stringAttr(target.image) ?? stringAttr(attrs.image);
  const digestAttr = stringAttr(target.digest) ?? stringAttr(attrs.digest);

  if (fromKey) {
    if (projectAttr && projectAttr !== fromKey.projectId) {
      failIdentity('Container asset projectId does not match gcr: identity — refusing pull');
    }
    if (locationAttr && locationAttr !== fromKey.location) {
      failIdentity('Container asset location does not match gcr: identity — refusing pull');
    }
    if (repoAttr && repoAttr !== fromKey.repository) {
      failIdentity('Container asset repository does not match gcr: identity — refusing pull');
    }
    if (imageAttr && imageAttr !== fromKey.image) {
      failIdentity('Container asset image does not match gcr: identity — refusing pull');
    }
    if (digestAttr) {
      if (!SHA256_DIGEST_RE.test(digestAttr)) {
        failIdentity(`Refusing non-digest container attribute digest '${digestAttr}'`);
      }
      if (digestAttr.toLowerCase() !== fromKey.digest) {
        failIdentity('Container asset digest does not match gcr: identity — refusing pull');
      }
    }
    const location = resolveGcrLocation(fromKey.location, target, options);
    return { kind: 'gcr', ...fromKey, location };
  }

  if (
    projectAttr &&
    GCP_PROJECT_ID_RE.test(projectAttr) &&
    repoAttr &&
    GCR_REPOSITORY_ID_RE.test(repoAttr) &&
    imageAttr &&
    digestAttr &&
    SHA256_DIGEST_RE.test(digestAttr)
  ) {
    const parts = {
      projectId: projectAttr,
      location: resolveGcrLocation(undefined, target, options),
      repository: repoAttr,
      image: imageAttr,
      digest: digestAttr.toLowerCase(),
    };
    assertGcrIdentityParts(parts);
    return { kind: 'gcr', ...parts };
  }

  failIdentity(
    'Refusing container_image without gcr:{project}/{location}/{repository}/{image}@sha256:<digest> identity — no tag fallback, no other registry',
  );
}

/**
 * Parse `externalKey` / attributes for
 * `acr:{subscriptionId}/{resourceGroup}/{registry}/{repository}@sha256:<digest>`.
 * Subscription / resource group / registry / repository are ids — never a
 * tenant `azurecr.io` host. Pull host is derived as `{registry}.azurecr.io`.
 * An ARM-derived `loginServer` attribute is consistency-checked only.
 */
export function parseAcrImageRef(
  target: Record<string, unknown>,
  options: Record<string, unknown> = {},
): AcrImageRef {
  refuseTenantWritableRegistry(options);
  refuseTenantWritableRegistry(target);

  const key = typeof target.externalKey === 'string' ? target.externalKey.trim() : '';
  let fromKey:
    | { subscriptionId: string; resourceGroup: string; registry: string; repository: string; digest: string }
    | undefined;
  if (key) {
    const match = ACR_EXTERNAL_KEY_RE.exec(key);
    if (!match) {
      failIdentity(
        `Refusing non-digest or malformed container identity '${key}' — expected acr:{subscriptionId}/{resourceGroup}/{registry}/{repository}@sha256:<64 hex>`,
      );
    }
    fromKey = {
      subscriptionId: match[1]!.toLowerCase(),
      resourceGroup: match[2]!,
      registry: match[3]!.toLowerCase(),
      repository: match[4]!,
      digest: match[5]!.toLowerCase(),
    };
    assertAcrIdentityParts(fromKey);
  }

  const attrs = asRecord(target.attributes);
  const subscriptionAttr =
    stringAttr(target.subscriptionId) ?? stringAttr(attrs.subscriptionId);
  const rgAttr = stringAttr(target.resourceGroup) ?? stringAttr(attrs.resourceGroup);
  const registryAttr = stringAttr(target.registry) ?? stringAttr(attrs.registry);
  const repoAttr = stringAttr(target.repository) ?? stringAttr(attrs.repository);
  const digestAttr = stringAttr(target.digest) ?? stringAttr(attrs.digest);

  if (fromKey) {
    if (subscriptionAttr && subscriptionAttr.toLowerCase() !== fromKey.subscriptionId) {
      failIdentity('Container asset subscriptionId does not match acr: identity — refusing pull');
    }
    if (rgAttr && rgAttr !== fromKey.resourceGroup) {
      failIdentity('Container asset resourceGroup does not match acr: identity — refusing pull');
    }
    if (registryAttr && registryAttr.toLowerCase() !== fromKey.registry) {
      failIdentity('Container asset registry does not match acr: identity — refusing pull');
    }
    if (repoAttr && repoAttr !== fromKey.repository) {
      failIdentity('Container asset repository does not match acr: identity — refusing pull');
    }
    if (digestAttr) {
      if (!SHA256_DIGEST_RE.test(digestAttr)) {
        failIdentity(`Refusing non-digest container attribute digest '${digestAttr}'`);
      }
      if (digestAttr.toLowerCase() !== fromKey.digest) {
        failIdentity('Container asset digest does not match acr: identity — refusing pull');
      }
    }
    pinAcrLoginServerAttr(fromKey.registry, target, options);
    return { kind: 'acr', ...fromKey };
  }

  if (
    subscriptionAttr &&
    AZURE_GUID_RE.test(subscriptionAttr) &&
    rgAttr &&
    registryAttr &&
    ACR_REGISTRY_NAME_RE.test(registryAttr) &&
    repoAttr &&
    digestAttr &&
    SHA256_DIGEST_RE.test(digestAttr)
  ) {
    const parts = {
      subscriptionId: subscriptionAttr.toLowerCase(),
      resourceGroup: rgAttr,
      registry: registryAttr.toLowerCase(),
      repository: repoAttr,
      digest: digestAttr.toLowerCase(),
    };
    assertAcrIdentityParts(parts);
    pinAcrLoginServerAttr(parts.registry, target, options);
    return { kind: 'acr', ...parts };
  }

  failIdentity(
    'Refusing container_image without acr:{subscriptionId}/{resourceGroup}/{registry}/{repository}@sha256:<digest> identity — no tag fallback, no other registry',
  );
}

/**
 * Accept GHCR, ECR, GCR/Artifact Registry, or ACR digest identities. Other
 * registries (Docker Hub, Quay) are refused. Pull is by digest only.
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
    if (GCR_EXTERNAL_KEY_RE.test(key)) {
      return parseGcrImageRef(target, options);
    }
    if (ACR_EXTERNAL_KEY_RE.test(key)) {
      return parseAcrImageRef(target, options);
    }
    failIdentity(
      `Refusing non-digest or malformed container identity '${key}' — expected ghcr:owner/name@sha256:<64 hex>, ecr:{accountId}/{repositoryName}@sha256:<64 hex>, gcr:{project}/{location}/{repository}/{image}@sha256:<64 hex>, or acr:{subscriptionId}/{resourceGroup}/{registry}/{repository}@sha256:<64 hex>`,
    );
  }

  const attrs = asRecord(target.attributes);
  const ownerAttr = stringAttr(target.owner) ?? stringAttr(attrs.owner);
  const nameAttr = stringAttr(target.package) ?? stringAttr(attrs.package);
  const digestAttr = stringAttr(target.digest) ?? stringAttr(attrs.digest);
  const accountAttr = stringAttr(target.accountId) ?? stringAttr(attrs.accountId);
  const projectAttr = stringAttr(target.projectId) ?? stringAttr(attrs.projectId);
  const locationAttr = stringAttr(target.location) ?? stringAttr(attrs.location);
  const repoAttr = stringAttr(target.repository) ?? stringAttr(attrs.repository);
  const imageAttr = stringAttr(target.image) ?? stringAttr(attrs.image);
  const subscriptionAttr =
    stringAttr(target.subscriptionId) ?? stringAttr(attrs.subscriptionId);
  const registryAttr = stringAttr(target.registry) ?? stringAttr(attrs.registry);

  if (
    projectAttr &&
    GCP_PROJECT_ID_RE.test(projectAttr) &&
    (locationAttr || stringAttr(options.location)) &&
    repoAttr &&
    imageAttr &&
    digestAttr &&
    SHA256_DIGEST_RE.test(digestAttr)
  ) {
    return parseGcrImageRef(target, options);
  }
  if (
    subscriptionAttr &&
    AZURE_GUID_RE.test(subscriptionAttr) &&
    registryAttr &&
    ACR_REGISTRY_NAME_RE.test(registryAttr) &&
    repoAttr &&
    digestAttr &&
    SHA256_DIGEST_RE.test(digestAttr)
  ) {
    return parseAcrImageRef(target, options);
  }
  if (ownerAttr && nameAttr && digestAttr && SHA256_DIGEST_RE.test(digestAttr) && !accountAttr) {
    return { kind: 'ghcr', ...parseGhcrImageRef(target, options) };
  }
  if (accountAttr && AWS_ACCOUNT_RE.test(accountAttr)) {
    return parseEcrImageRef(target, options);
  }

  failIdentity(
    'Refusing container_image without ghcr:, ecr:, gcr:, or acr: digest identity — no tag fallback, no other registry',
  );
}

function assertGcrIdentityParts(parts: {
  projectId: string;
  location: string;
  repository: string;
  image: string;
}): void {
  assertProjectId(parts.projectId);
  assertLocationId(parts.location);
  if (!GCR_REPOSITORY_ID_RE.test(parts.repository) || /^https?:\/\//i.test(parts.repository)) {
    failIdentity(
      `Refusing Artifact Registry repository '${parts.repository}' — not a valid repository identifier`,
    );
  }
  if (!parts.image || /^https?:\/\//i.test(parts.image.trim()) || parts.image.includes('@')) {
    failIdentity(
      `Refusing Artifact Registry image '${parts.image}' — image is a path id, not a registry host`,
    );
  }
}

function assertAcrIdentityParts(parts: {
  subscriptionId: string;
  resourceGroup: string;
  registry: string;
  repository: string;
}): void {
  wrapAzureIdentity(() => assertAzureGuid(parts.subscriptionId, 'subscriptionId'));
  wrapAzureIdentity(() => assertAzureResourceGroup(parts.resourceGroup));
  wrapAzureIdentity(() => assertAcrRegistryName(parts.registry));
  wrapAzureIdentity(() => assertAcrRepository(parts.repository));
}

function pinAcrLoginServerAttr(
  registry: string,
  target: Record<string, unknown>,
  options: Record<string, unknown>,
): void {
  const attrs = asRecord(target.attributes);
  const fromTarget = stringAttr(target.loginServer) ?? stringAttr(attrs.loginServer);
  const fromOptions = stringAttr(options.loginServer) ?? stringAttr(options.login_server);
  if (fromTarget) wrapAzureIdentity(() => assertAcrLoginServer(registry, fromTarget));
  if (fromOptions) wrapAzureIdentity(() => assertAcrLoginServer(registry, fromOptions));
}

function wrapAzureIdentity<T>(fn: () => T): T {
  try {
    return fn();
  } catch (err) {
    if (err instanceof AzureEgressError) {
      throw new ContainerEgressError(err.message);
    }
    throw err;
  }
}

function resolveGcrLocation(
  fromKey: string | undefined,
  target: Record<string, unknown>,
  options: Record<string, unknown>,
): string {
  const attrs = asRecord(target.attributes);
  const fromTarget = stringAttr(target.location) ?? stringAttr(attrs.location);
  const fromOptions = stringAttr(options.location);
  if (fromKey && fromTarget && fromKey !== fromTarget) {
    failIdentity('Container asset location does not match gcr: identity — refusing pull');
  }
  if (fromKey && fromOptions && fromKey !== fromOptions) {
    failIdentity('Container asset location does not match integration location — refusing pull');
  }
  if (fromTarget && fromOptions && fromTarget !== fromOptions) {
    failIdentity('Container asset location does not match integration location — refusing pull');
  }
  const location = fromKey ?? fromTarget ?? fromOptions;
  if (!location) {
    failIdentity(
      'Refusing GCR pull without a location id — location comes from the gcr: identity, not a pkg.dev host',
    );
  }
  return assertLocationId(location);
}

function assertProjectId(projectId: string): string {
  if (/^https?:\/\//i.test(projectId.trim()) || /pkg\.dev/i.test(projectId)) {
    throw new ContainerEgressError(
      "Refusing tenant-writable container registry endpoint (projectId) — project is an id, not a host",
    );
  }
  if (!GCP_PROJECT_ID_RE.test(projectId)) {
    failIdentity(`Refusing GCP projectId '${projectId}' — not a valid GCP project identifier`);
  }
  return projectId;
}

function assertLocationId(location: string): string {
  if (/^https?:\/\//i.test(location.trim()) || /pkg\.dev/i.test(location) || location.includes('.')) {
    throw new ContainerEgressError(
      "Refusing tenant-writable container registry endpoint (location) — location is an id, not a host",
    );
  }
  if (!GCP_LOCATION_ID_RE.test(location)) {
    failIdentity(
      `Refusing GCP location '${location}' — not a valid Artifact Registry location identifier`,
    );
  }
  return location;
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
