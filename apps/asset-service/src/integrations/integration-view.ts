import { IntegrationView } from '@ctem/contracts';
import { scrubText } from '../secrets/scrub';

export interface IntegrationViewSource {
  id: string;
  provider: string;
  displayName: string;
  config: unknown;
  credentialRef: string | null;
  enabled: boolean;
  lastSyncAt: Date | null;
  lastSyncError: string | null;
  secret: { integrationId: string } | null;
}

export function toIntegrationView(row: IntegrationViewSource): IntegrationView {
  const raw =
    row.config && typeof row.config === 'object' ? (row.config as Record<string, unknown>) : {};
  const owner = typeof raw.owner === 'string' ? raw.owner : '';
  const ownerType = raw.ownerType === 'org' || raw.ownerType === 'user' ? raw.ownerType : 'user';
  const secretRef = row.credentialRef?.startsWith('secret:') ?? false;
  const hasCredential = secretRef ? row.secret != null : Boolean(row.credentialRef);
  return IntegrationView.parse({
    id: row.id,
    provider: row.provider,
    displayName: row.displayName,
    owner,
    ownerType,
    enabled: row.enabled,
    hasCredential,
    lastSyncAt: row.lastSyncAt ? row.lastSyncAt.toISOString() : null,
    lastSyncError: row.lastSyncError ? scrubText(row.lastSyncError) : null,
  });
}
