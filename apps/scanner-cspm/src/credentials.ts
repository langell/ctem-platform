import { createPrivateKey } from 'node:crypto';

/**
 * Same platform-operated `env:` allowlist as AWS/GCP/Azure discovery.
 * A tenant-supplied credentialRef cannot read DATABASE_URL, PATH, or other
 * replica secrets. CSPM has no public-listing fallback.
 */

const ENV_ALLOWLIST = /^(GITHUB|GITLAB|AWS|GCP|AZURE)_[A-Z0-9_]+$/;

export class CspmCredentialError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CspmCredentialError';
  }
}

export function resolveCredential(ref: string | null): string | undefined {
  if (!ref) return undefined;

  const sep = ref.indexOf(':');
  const scheme = sep === -1 ? ref : ref.slice(0, sep);
  const key = sep === -1 ? '' : ref.slice(sep + 1);

  if (scheme === 'env') {
    if (!key || !ENV_ALLOWLIST.test(key)) {
      throw new CspmCredentialError(
        `credentialRef 'env:${key || '<empty>'}' is not allowlisted — env: is platform-operated and only GITHUB_* / GITLAB_* / AWS_* / GCP_* / AZURE_* names are permitted`,
      );
    }
    return process.env[key] || undefined;
  }

  throw new CspmCredentialError(
    `Unsupported credentialRef scheme '${scheme}' — only 'env:<VAR>' is implemented`,
  );
}

export interface AwsCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
}

const AWS_ENV_NAME = /^AWS_[A-Z0-9_]+$/;

export function requireAwsCredentials(credentialRef: string | null): AwsCredentials {
  if (!credentialRef) {
    throw new CspmCredentialError(
      'Cloud posture requires a usable credentialRef (env:AWS_*) — refusing unauthenticated evaluate',
    );
  }

  const sep = credentialRef.indexOf(':');
  const scheme = sep === -1 ? credentialRef : credentialRef.slice(0, sep);
  const key = sep === -1 ? '' : credentialRef.slice(sep + 1);
  if (scheme !== 'env' || !key || !AWS_ENV_NAME.test(key)) {
    resolveCredential(credentialRef);
    throw new CspmCredentialError(
      `credentialRef '${credentialRef}' is not an env:AWS_* pointer — cloud posture only accepts platform-operated AWS_* names`,
    );
  }

  const pointed = resolveCredential(credentialRef);
  if (!pointed) {
    throw new CspmCredentialError(
      `credentialRef '${credentialRef}' is set but cannot be used — refusing to evaluate without usable AWS_* credentials`,
    );
  }

  const accessKeyId = resolveCredential('env:AWS_ACCESS_KEY_ID');
  const secretAccessKey = resolveCredential('env:AWS_SECRET_ACCESS_KEY');
  if (!accessKeyId || !secretAccessKey) {
    throw new CspmCredentialError(
      'Cloud posture fails closed without usable AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY',
    );
  }

  const sessionToken = resolveCredential('env:AWS_SESSION_TOKEN');
  return { accessKeyId, secretAccessKey, ...(sessionToken ? { sessionToken } : {}) };
}

export interface GcpCredentials {
  clientEmail: string;
  privateKey: string;
}

const GCP_ENV_NAME = /^GCP_[A-Z0-9_]+$/;

export function normalizeGcpPrivateKey(pem: string): string {
  return pem.includes('-----BEGIN') ? pem.replace(/\\n/g, '\n').trim() : pem.trim();
}

function assertUsableGcpPrivateKey(pem: string): void {
  try {
    createPrivateKey(normalizeGcpPrivateKey(pem));
  } catch {
    throw new CspmCredentialError('Cloud posture fails closed — GCP_PRIVATE_KEY is unusable');
  }
}

export function requireGcpCredentials(credentialRef: string | null): GcpCredentials {
  if (!credentialRef) {
    throw new CspmCredentialError(
      'Cloud posture requires a usable credentialRef (env:GCP_*) — refusing unauthenticated evaluate',
    );
  }

  const sep = credentialRef.indexOf(':');
  const scheme = sep === -1 ? credentialRef : credentialRef.slice(0, sep);
  const key = sep === -1 ? '' : credentialRef.slice(sep + 1);
  if (scheme !== 'env' || !key || !GCP_ENV_NAME.test(key)) {
    resolveCredential(credentialRef);
    throw new CspmCredentialError(
      `credentialRef '${credentialRef}' is not an env:GCP_* pointer — cloud posture only accepts platform-operated GCP_* names`,
    );
  }

  const pointed = resolveCredential(credentialRef);
  if (!pointed) {
    throw new CspmCredentialError(
      `credentialRef '${credentialRef}' is set but cannot be used — refusing to evaluate without usable GCP_* credentials`,
    );
  }

  const clientEmail = resolveCredential('env:GCP_CLIENT_EMAIL');
  const privateKey = resolveCredential('env:GCP_PRIVATE_KEY');
  if (!clientEmail || !privateKey) {
    throw new CspmCredentialError(
      'Cloud posture fails closed without usable GCP_CLIENT_EMAIL and GCP_PRIVATE_KEY',
    );
  }
  if (!clientEmail.includes('@') || /\s/.test(clientEmail)) {
    throw new CspmCredentialError('Cloud posture fails closed — GCP_CLIENT_EMAIL is unusable');
  }
  assertUsableGcpPrivateKey(privateKey);

  return { clientEmail, privateKey };
}

export interface AzureCredentials {
  tenantId: string;
  clientId: string;
  clientSecret: string;
}

const AZURE_ENV_NAME = /^AZURE_[A-Z0-9_]+$/;
const AZURE_GUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function assertUsableAzureGuid(value: string, envName: string): string {
  const trimmed = value.trim();
  if (!AZURE_GUID_RE.test(trimmed) || /^https?:\/\//i.test(trimmed)) {
    throw new CspmCredentialError(`Cloud posture fails closed — ${envName} is unusable`);
  }
  return trimmed.toLowerCase();
}

export function requireAzureCredentials(credentialRef: string | null): AzureCredentials {
  if (!credentialRef) {
    throw new CspmCredentialError(
      'Cloud posture requires a usable credentialRef (env:AZURE_*) — refusing unauthenticated evaluate',
    );
  }

  const sep = credentialRef.indexOf(':');
  const scheme = sep === -1 ? credentialRef : credentialRef.slice(0, sep);
  const key = sep === -1 ? '' : credentialRef.slice(sep + 1);
  if (scheme !== 'env' || !key || !AZURE_ENV_NAME.test(key)) {
    resolveCredential(credentialRef);
    throw new CspmCredentialError(
      `credentialRef '${credentialRef}' is not an env:AZURE_* pointer — cloud posture only accepts platform-operated AZURE_* names`,
    );
  }

  const pointed = resolveCredential(credentialRef);
  if (!pointed) {
    throw new CspmCredentialError(
      `credentialRef '${credentialRef}' is set but cannot be used — refusing to evaluate without usable AZURE_* credentials`,
    );
  }

  const tenantId = resolveCredential('env:AZURE_TENANT_ID');
  const clientId = resolveCredential('env:AZURE_CLIENT_ID');
  const clientSecret = resolveCredential('env:AZURE_CLIENT_SECRET');
  const secret = clientSecret?.trim();
  if (!tenantId || !clientId || !secret) {
    throw new CspmCredentialError(
      'Cloud posture fails closed without usable AZURE_TENANT_ID, AZURE_CLIENT_ID, and AZURE_CLIENT_SECRET',
    );
  }

  return {
    tenantId: assertUsableAzureGuid(tenantId, 'AZURE_TENANT_ID'),
    clientId: assertUsableAzureGuid(clientId, 'AZURE_CLIENT_ID'),
    clientSecret: secret,
  };
}
