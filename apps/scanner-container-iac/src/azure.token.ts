import type { AzureCredentials } from './container.credential';
import {
  ACR_AAD_SCOPE,
  AzureEgressError,
  allowlistedAzureTokenUrl,
  azureTokenUrl,
} from './azure.egress';

/**
 * Exchange client credentials at login.microsoftonline.com only. The client
 * secret never leaves the Azure host allowlist. Tenant id is a path
 * identifier on that host — never a destination.
 *
 * `scope` is platform-allowlisted (ACR AAD audience). Tenant config cannot
 * choose a token host or a custom scope.
 */
export async function exchangeAzureAccessToken(
  creds: AzureCredentials,
  fetchImpl: (url: string | URL, init?: RequestInit) => Promise<Response> = globalThis.fetch.bind(
    globalThis,
  ),
  scope: string = ACR_AAD_SCOPE,
): Promise<string> {
  if (scope !== ACR_AAD_SCOPE) {
    throw new AzureEgressError(
      'Refusing Azure token scope that is not allowlisted — only the ACR AAD audience is permitted',
    );
  }
  const url = allowlistedAzureTokenUrl(azureTokenUrl(creds.tenantId));
  const body = new URLSearchParams({
    grant_type: 'client_credentials',
    client_id: creds.clientId,
    client_secret: creds.clientSecret,
    scope,
  }).toString();
  const res = await fetchImpl(url, {
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
