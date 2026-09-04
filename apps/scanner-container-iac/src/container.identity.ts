/**
 * GHCR image identity. Discovery (#34) keys container_image assets as
 * `ghcr:owner/name@sha256:<64 hex>` — content digest, never a mutable tag.
 */

import { ContainerEgressError, refuseTenantWritableRegistry } from './container.egress';

export const SHA256_DIGEST_RE = /^sha256:[a-f0-9]{64}$/i;
export const GHCR_EXTERNAL_KEY_RE = /^ghcr:([^/@]+)\/(.+)@(sha256:[a-f0-9]{64})$/i;

export class ContainerIdentityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ContainerIdentityError';
  }
}

export interface GhcrImageRef {
  owner: string;
  name: string;
  digest: string;
}

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
