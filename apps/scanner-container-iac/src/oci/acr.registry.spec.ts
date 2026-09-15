import { afterEach, describe, expect, it, vi } from 'vitest';
import { gzipSync } from 'node:zlib';
import { AcrRegistry } from './acr.registry';
import { ContainerPullError } from './registry';
import { packTar } from './test-tar';

const DIGEST = `sha256:${'a'.repeat(64)}`;
const LAYER = `sha256:${'b'.repeat(64)}`;
const CONFIG = `sha256:${'c'.repeat(64)}`;
const SUB = '11111111-1111-1111-1111-111111111111';
const TENANT = '22222222-2222-2222-2222-222222222222';
const REGISTRY = 'acmeprod';
const HOST = `${REGISTRY}.azurecr.io`;
const AAD = `https://login.microsoftonline.com/${TENANT}/oauth2/v2.0/token`;
const CREDS = {
  tenantId: TENANT,
  clientId: '33333333-3333-3333-3333-333333333333',
  clientSecret: 'super-secret',
};
const REF = {
  kind: 'acr' as const,
  subscriptionId: SUB,
  resourceGroup: 'rg-prod',
  registry: REGISTRY,
  repository: 'payments-api',
  digest: DIGEST,
};

function jsonResponse(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });
}

function imageManifest() {
  return {
    schemaVersion: 2,
    mediaType: 'application/vnd.oci.image.manifest.v1+json',
    config: { mediaType: 'application/vnd.oci.image.config.v1+json', digest: CONFIG, size: 2 },
    layers: [
      {
        mediaType: 'application/vnd.oci.image.layer.v1.tar+gzip',
        digest: LAYER,
        size: 10,
      },
    ],
  };
}

describe('AcrRegistry.pull', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('pulls a mocked ACR digest via login.microsoftonline.com + pinned azurecr.io', async () => {
    const tar = packTar({ 'lib/apk/db/installed': 'P:openssl\nV:1.1.1w\n\n' });
    const gz = gzipSync(tar);
    const fetchFn = vi.fn(async (url: string | URL, init?: RequestInit) => {
      const href = String(url);
      if (href === AAD) {
        expect(init?.method).toBe('POST');
        expect(String(init?.body)).toContain('client_secret=super-secret');
        expect(String(init?.body)).toContain(
          encodeURIComponent('https://containerregistry.azure.net/.default'),
        );
        return jsonResponse({ access_token: 'aad-token' });
      }
      expect(href.startsWith(`https://${HOST}/`)).toBe(true);
      if (href.endsWith('/oauth2/exchange')) {
        expect(init?.method).toBe('POST');
        expect(String(init?.body)).toContain('access_token=aad-token');
        return jsonResponse({ refresh_token: 'acr-refresh' });
      }
      if (href.endsWith('/oauth2/token')) {
        expect(init?.method).toBe('POST');
        expect(String(init?.body)).toContain('refresh_token=acr-refresh');
        expect(String(init?.body)).toContain(encodeURIComponent('repository:payments-api:pull'));
        return jsonResponse({ access_token: 'registry-token' });
      }
      if (href.includes('/manifests/')) {
        expect((init?.headers as Record<string, string>).authorization).toBe('Bearer registry-token');
        return jsonResponse(imageManifest());
      }
      if (href.includes('/blobs/')) return new Response(gz, { status: 200 });
      throw new Error(`unexpected url ${href}`);
    });

    const registry = new AcrRegistry(fetchFn as unknown as typeof fetch);
    const pulled = await registry.pull(REF, CREDS, () => true);
    expect(pulled.layers).toHaveLength(1);
    expect(pulled.layers[0]?.digest).toBe(LAYER);
    expect(pulled.layers[0]?.files.has('lib/apk/db/installed')).toBe(true);
    expect(
      fetchFn.mock.calls.every((c) => {
        const href = String(c[0]);
        return href.startsWith('https://login.microsoftonline.com/') || href.startsWith(`https://${HOST}/`);
      }),
    ).toBe(true);
    expect(fetchFn.mock.calls.some((c) => String(c[0]).includes('azurecr.io.evil'))).toBe(false);
    expect(fetchFn.mock.calls.some((c) => String(c[0]).includes('ghcr.io'))).toBe(false);
    expect(fetchFn.mock.calls.some((c) => String(c[0]).includes('pkg.dev'))).toBe(false);
    expect(fetchFn.mock.calls.some((c) => String(c[0]).includes('management.azure.com'))).toBe(false);
  });

  it('follows a same-host blob redirect with the ACR token', async () => {
    const tar = packTar({ 'lib/apk/db/installed': 'P:openssl\nV:1.1.1w\n\n' });
    const gz = gzipSync(tar);
    const next = `https://${HOST}/v2/payments-api/blobs/${LAYER}?sig=1`;
    const fetchFn = vi.fn(async (url: string | URL, init?: RequestInit) => {
      const href = String(url);
      if (href === AAD) return jsonResponse({ access_token: 'aad-token' });
      if (href.endsWith('/oauth2/exchange')) return jsonResponse({ refresh_token: 'acr-refresh' });
      if (href.endsWith('/oauth2/token')) return jsonResponse({ access_token: 'registry-token' });
      if (href.includes('/manifests/')) return jsonResponse(imageManifest());
      if (href.includes('/blobs/') && !href.includes('sig=1')) {
        return new Response(null, { status: 302, headers: { location: next } });
      }
      if (href === next) {
        expect((init?.headers as Record<string, string>).authorization).toBe('Bearer registry-token');
        return new Response(gz, { status: 200 });
      }
      throw new Error(`unexpected url ${href}`);
    });

    const registry = new AcrRegistry(fetchFn as unknown as typeof fetch);
    const pulled = await registry.pull(REF, CREDS, () => true);
    expect(pulled.layers).toHaveLength(1);
  });

  it('refuses a suffix-confused azurecr.io blob redirect', async () => {
    const fetchFn = vi.fn(async (url: string | URL) => {
      const href = String(url);
      if (href === AAD) return jsonResponse({ access_token: 'aad-token' });
      if (href.endsWith('/oauth2/exchange')) return jsonResponse({ refresh_token: 'acr-refresh' });
      if (href.endsWith('/oauth2/token')) return jsonResponse({ access_token: 'registry-token' });
      if (href.includes('/manifests/')) return jsonResponse(imageManifest());
      if (href.includes('/blobs/')) {
        return new Response(null, {
          status: 302,
          headers: { location: 'https://acmeprod.azurecr.io.evil.example/blob' },
        });
      }
      throw new Error(`unexpected url ${href}`);
    });
    await expect(
      new AcrRegistry(fetchFn as unknown as typeof fetch).pull(REF, CREDS, () => true),
    ).rejects.toThrow(/azurecr\.io|redirect host/);
  });

  it('refuses a data.azurecr.io or other-registry blob redirect', async () => {
    const fetchFn = vi.fn(async (url: string | URL) => {
      const href = String(url);
      if (href === AAD) return jsonResponse({ access_token: 'aad-token' });
      if (href.endsWith('/oauth2/exchange')) return jsonResponse({ refresh_token: 'acr-refresh' });
      if (href.endsWith('/oauth2/token')) return jsonResponse({ access_token: 'registry-token' });
      if (href.includes('/manifests/')) return jsonResponse(imageManifest());
      if (href.includes('/blobs/')) {
        return new Response(null, {
          status: 302,
          headers: { location: 'https://acmeprod.eastus.data.azurecr.io/blob' },
        });
      }
      throw new Error(`unexpected url ${href}`);
    });
    await expect(
      new AcrRegistry(fetchFn as unknown as typeof fetch).pull(REF, CREDS, () => true),
    ).rejects.toThrow(/azurecr\.io|redirect host/);
  });

  it('fails closed when Azure token exchange or the blob GET is not ok', async () => {
    const denied = vi.fn(async () => new Response('nope', { status: 403 }));
    await expect(
      new AcrRegistry(denied as unknown as typeof fetch).pull(REF, CREDS, () => true),
    ).rejects.toThrow(/token/);

    const fetchFn = vi.fn(async (url: string | URL) => {
      const href = String(url);
      if (href === AAD) return jsonResponse({ access_token: 'aad-token' });
      if (href.endsWith('/oauth2/exchange')) return jsonResponse({ refresh_token: 'acr-refresh' });
      if (href.endsWith('/oauth2/token')) return jsonResponse({ access_token: 'registry-token' });
      if (href.includes('/manifests/')) return jsonResponse(imageManifest());
      return new Response('nope', { status: 502 });
    });
    await expect(
      new AcrRegistry(fetchFn as unknown as typeof fetch).pull(REF, CREDS, () => true),
    ).rejects.toThrow(ContainerPullError);
  });

  it('throws when the deadline fires mid-pull', async () => {
    let calls = 0;
    const fetchFn = vi.fn(async (url: string | URL) => {
      const href = String(url);
      if (href === AAD) return jsonResponse({ access_token: 'aad-token' });
      if (href.endsWith('/oauth2/exchange')) return jsonResponse({ refresh_token: 'r' });
      if (href.endsWith('/oauth2/token')) return jsonResponse({ access_token: 't' });
      if (href.includes('/manifests/')) return jsonResponse(imageManifest());
      return new Response(gzipSync(packTar({ 'etc/os-release': 'ID=alpine\n' })), { status: 200 });
    });
    await expect(
      new AcrRegistry(fetchFn as unknown as typeof fetch).pull(REF, CREDS, () => {
        calls += 1;
        return calls < 2;
      }),
    ).rejects.toThrow(/deadline/);
  });

  it('fails closed when the image manifest omits layers', async () => {
    const fetchFn = vi.fn(async (url: string | URL) => {
      const href = String(url);
      if (href === AAD) return jsonResponse({ access_token: 'aad-token' });
      if (href.endsWith('/oauth2/exchange')) return jsonResponse({ refresh_token: 'acr-refresh' });
      if (href.endsWith('/oauth2/token')) return jsonResponse({ access_token: 'registry-token' });
      return jsonResponse({ schemaVersion: 2, mediaType: 'application/vnd.oci.image.manifest.v1+json' });
    });
    await expect(
      new AcrRegistry(fetchFn as unknown as typeof fetch).pull(REF, CREDS, () => true),
    ).rejects.toThrow(/missing layers/);
  });
});
