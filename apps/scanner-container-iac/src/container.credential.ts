/**
 * Same allowlist as GHCR / ECR / GCR / ACR discovery (`apps/asset-service` credentials).
 * Platform-operated `env:GITHUB_*` (GHCR), `env:AWS_*` (ECR), `env:GCP_*`
 * (GCR / Artifact Registry), and `env:AZURE_*` (ACR). A missing or unusable
 * pointer must fail the pull — never empty-succeed.
 */

import { createPrivateKey } from 'node:crypto';

const ENV_ALLOWLIST = /^(GITHUB|GITLAB|AWS|GCP|AZURE)_[A-Z0-9_]+$/;
const GITHUB_ENV_NAME = /^GITHUB_[A-Z0-9_]+$/;
const AWS_ENV_NAME = /^AWS_[A-Z0-9_]+$/;
const GCP_ENV_NAME = /^GCP_[A-Z0-9_]+$/;
const AZURE_ENV_NAME = /^AZURE_[A-Z0-9_]+$/;
const AZURE_GUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export class ContainerCredentialError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ContainerCredentialError';
  }
}

function resolveCredential(ref: string | null): string | undefined {
  if (!ref) return undefined;

  const sep = ref.indexOf(':');
  const scheme = sep === -1 ? ref : ref.slice(0, sep);
  const key = sep === -1 ? '' : ref.slice(sep + 1);

  if (scheme === 'env') {
    if (!key || !ENV_ALLOWLIST.test(key)) {
      throw new ContainerCredentialError(
        `credentialRef 'env:${key || '<empty>'}' is not allowlisted — env: is platform-operated and only GITHUB_* / GITLAB_* / AWS_* / GCP_* / AZURE_* names are permitted`,
      );
    }
    return process.env[key] || undefined;
  }

  throw new ContainerCredentialError(
    `Unsupported credentialRef scheme '${scheme}' — only 'env:<VAR>' is implemented`,
  );
}

/**
 * Private GHCR pulls have no unauthenticated path. The integration pointer
 * must be `env:GITHUB_*` (same as discovery — not `GHCR_*`), and the pointed
 * token must be usable.
 */
export function requireGithubToken(credentialRef: string | null): string {
  if (!credentialRef) {
    throw new ContainerCredentialError(
      'Private GHCR pull requires a usable credentialRef (env:GITHUB_*) — refusing unauthenticated pull',
    );
  }

  const sep = credentialRef.indexOf(':');
  const scheme = sep === -1 ? credentialRef : credentialRef.slice(0, sep);
  const key = sep === -1 ? '' : credentialRef.slice(sep + 1);
  if (scheme !== 'env' || !key || !GITHUB_ENV_NAME.test(key)) {
    resolveCredential(credentialRef);
    throw new ContainerCredentialError(
      `credentialRef '${credentialRef}' is not an env:GITHUB_* pointer — GHCR pulls only accept platform-operated GITHUB_* names`,
    );
  }

  const token = resolveCredential(credentialRef);
  if (!token || !token.trim()) {
    throw new ContainerCredentialError(
      `credentialRef '${credentialRef}' is set but cannot be used — refusing to pull without usable GITHUB_* credentials`,
    );
  }

  return token.trim();
}

/** Public images may omit credentials; a set-but-unusable GITHUB_* pointer still fails. */
export function optionalGithubToken(credentialRef: string | null): string | undefined {
  if (!credentialRef) return undefined;
  return requireGithubToken(credentialRef);
}

export interface AwsCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
}

/**
 * ECR pulls have no unauthenticated path (same class as ECR discovery).
 * The integration pointer must be `env:AWS_*`, and the platform-operated
 * signing pair `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` must both be
 * usable. A missing or unusable pointer must not empty-succeed.
 */
export function requireAwsCredentials(credentialRef: string | null): AwsCredentials {
  if (!credentialRef) {
    throw new ContainerCredentialError(
      'ECR pull requires a usable credentialRef (env:AWS_*) — refusing unauthenticated pull',
    );
  }

  const sep = credentialRef.indexOf(':');
  const scheme = sep === -1 ? credentialRef : credentialRef.slice(0, sep);
  const key = sep === -1 ? '' : credentialRef.slice(sep + 1);
  if (scheme !== 'env' || !key || !AWS_ENV_NAME.test(key)) {
    resolveCredential(credentialRef);
    throw new ContainerCredentialError(
      `credentialRef '${credentialRef}' is not an env:AWS_* pointer — ECR pulls only accept platform-operated AWS_* names`,
    );
  }

  const pointed = resolveCredential(credentialRef);
  if (!pointed) {
    throw new ContainerCredentialError(
      `credentialRef '${credentialRef}' is set but cannot be used — refusing to pull without usable AWS_* credentials`,
    );
  }

  const accessKeyId = resolveCredential('env:AWS_ACCESS_KEY_ID');
  const secretAccessKey = resolveCredential('env:AWS_SECRET_ACCESS_KEY');
  if (!accessKeyId || !secretAccessKey) {
    throw new ContainerCredentialError(
      'ECR pull fails closed without usable AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY',
    );
  }

  const sessionToken = resolveCredential('env:AWS_SESSION_TOKEN');
  return { accessKeyId, secretAccessKey, ...(sessionToken ? { sessionToken } : {}) };
}

export interface GcpCredentials {
  clientEmail: string;
  privateKey: string;
}

/** Env PEM often stores literal `\n`; Node needs real newlines. */
export function normalizeGcpPrivateKey(pem: string): string {
  return pem.includes('-----BEGIN') ? pem.replace(/\\n/g, '\n').trim() : pem.trim();
}

function assertUsableGcpPrivateKey(pem: string): void {
  try {
    createPrivateKey(normalizeGcpPrivateKey(pem));
  } catch {
    throw new ContainerCredentialError('GCR pull fails closed — GCP_PRIVATE_KEY is unusable');
  }
}

/**
 * GCR / Artifact Registry pulls have no unauthenticated path (same class as
 * GCR discovery). The integration pointer must be `env:GCP_*`, and the
 * platform-operated signing pair `GCP_CLIENT_EMAIL` + `GCP_PRIVATE_KEY`
 * must both be usable. A missing or unusable pointer must not empty-succeed.
 */
export function requireGcpCredentials(credentialRef: string | null): GcpCredentials {
  if (!credentialRef) {
    throw new ContainerCredentialError(
      'GCR pull requires a usable credentialRef (env:GCP_*) — refusing unauthenticated pull',
    );
  }

  const sep = credentialRef.indexOf(':');
  const scheme = sep === -1 ? credentialRef : credentialRef.slice(0, sep);
  const key = sep === -1 ? '' : credentialRef.slice(sep + 1);
  if (scheme !== 'env' || !key || !GCP_ENV_NAME.test(key)) {
    resolveCredential(credentialRef);
    throw new ContainerCredentialError(
      `credentialRef '${credentialRef}' is not an env:GCP_* pointer — GCR pulls only accept platform-operated GCP_* names`,
    );
  }

  const pointed = resolveCredential(credentialRef);
  if (!pointed) {
    throw new ContainerCredentialError(
      `credentialRef '${credentialRef}' is set but cannot be used — refusing to pull without usable GCP_* credentials`,
    );
  }

  const clientEmail = resolveCredential('env:GCP_CLIENT_EMAIL');
  const privateKey = resolveCredential('env:GCP_PRIVATE_KEY');
  if (!clientEmail || !privateKey) {
    throw new ContainerCredentialError(
      'GCR pull fails closed without usable GCP_CLIENT_EMAIL and GCP_PRIVATE_KEY',
    );
  }
  if (!clientEmail.includes('@') || /\s/.test(clientEmail)) {
    throw new ContainerCredentialError('GCR pull fails closed — GCP_CLIENT_EMAIL is unusable');
  }
  assertUsableGcpPrivateKey(privateKey);

  return { clientEmail, privateKey };
}

export interface AzureCredentials {
  tenantId: string;
  clientId: string;
  clientSecret: string;
}

function assertUsableAzureGuid(value: string, envName: string): string {
  const trimmed = value.trim();
  if (!AZURE_GUID_RE.test(trimmed) || /^https?:\/\//i.test(trimmed)) {
    throw new ContainerCredentialError(`ACR pull fails closed — ${envName} is unusable`);
  }
  return trimmed.toLowerCase();
}

/**
 * ACR pulls have no unauthenticated path (same class as ACR discovery).
 * The integration pointer must be `env:AZURE_*`, and the platform-operated
 * client-credentials triple `AZURE_TENANT_ID` + `AZURE_CLIENT_ID` +
 * `AZURE_CLIENT_SECRET` must all be usable. A missing or unusable pointer
 * must not empty-succeed.
 */
export function requireAzureCredentials(credentialRef: string | null): AzureCredentials {
  if (!credentialRef) {
    throw new ContainerCredentialError(
      'ACR pull requires a usable credentialRef (env:AZURE_*) — refusing unauthenticated pull',
    );
  }

  const sep = credentialRef.indexOf(':');
  const scheme = sep === -1 ? credentialRef : credentialRef.slice(0, sep);
  const key = sep === -1 ? '' : credentialRef.slice(sep + 1);
  if (scheme !== 'env' || !key || !AZURE_ENV_NAME.test(key)) {
    resolveCredential(credentialRef);
    throw new ContainerCredentialError(
      `credentialRef '${credentialRef}' is not an env:AZURE_* pointer — ACR pulls only accept platform-operated AZURE_* names`,
    );
  }

  const pointed = resolveCredential(credentialRef);
  if (!pointed) {
    throw new ContainerCredentialError(
      `credentialRef '${credentialRef}' is set but cannot be used — refusing to pull without usable AZURE_* credentials`,
    );
  }

  const tenantId = resolveCredential('env:AZURE_TENANT_ID');
  const clientId = resolveCredential('env:AZURE_CLIENT_ID');
  const clientSecret = resolveCredential('env:AZURE_CLIENT_SECRET');
  const secret = clientSecret?.trim();
  if (!tenantId || !clientId || !secret) {
    throw new ContainerCredentialError(
      'ACR pull fails closed without usable AZURE_TENANT_ID, AZURE_CLIENT_ID, and AZURE_CLIENT_SECRET',
    );
  }

  return {
    tenantId: assertUsableAzureGuid(tenantId, 'AZURE_TENANT_ID'),
    clientId: assertUsableAzureGuid(clientId, 'AZURE_CLIENT_ID'),
    clientSecret: secret,
  };
}
