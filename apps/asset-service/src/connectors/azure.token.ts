import type { AzureCredentials } from './credentials';
import {
  AZURE_TOKEN_SCOPE,
  allowlistedAzureTokenUrl,
  azureTokenUrl,
} from './azure.egress';

/**
 * Exchange client credentials at login.microsoftonline.com only. The client
 * secret never leaves the Azure host allowlist. Tenant id is a path
 * identifier on that host — never a destination.
 */
export async function exchangeAzureAccessToken(creds: AzureCredentials): Promise<string> {
  const url = allowlistedAzureTokenUrl(azureTokenUrl(creds.tenantId));
  const body = new URLSearchParams({
    grant_type: 'client_credentials',
    client_id: creds.clientId,
    client_secret: creds.clientSecret,
    scope: AZURE_TOKEN_SCOPE,
  }).toString();
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body,
    signal: AbortSignal.timeout(20_000),
  });
  if (!res.ok) {
    throw new Error(`Azure token API returned ${res.status}`);
  }
  const json = (await res.json()) as { access_token?: unknown };
  if (typeof json.access_token !== 'string' || json.access_token.length === 0) {
    throw new Error('Azure token API did not return an access_token');
  }
  return json.access_token;
}
