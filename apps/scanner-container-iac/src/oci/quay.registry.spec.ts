import { afterEach, describe, expect, it, vi } from 'vitest';
import { gzipSync } from 'node:zlib';
import { QuayRegistry } from './quay.registry';
import { ContainerPullError } from './registry';
import { packTar } from './test-tar';

const DIGEST = `sha256:${'a'.repeat(64)}`;
const LAYER = `sha256:${'b'.repeat(64)}`;
const CONFIG = `sha256:${'c'.repeat(64)}`;
const HOST = 'quay.io';
const AUTH =
  'https://quay.io/v2/auth?service=quay.io&scope=repository%3Aacme%2Fpayments-api%3Apull';
const TOKEN = 'quay_test_token';
const REF = {
  kind: 'quay' as const,
  namespace: 'acme',
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

describe('QuayRegistry.pull', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('pulls a mocked Quay digest via quay.io /v2/auth + /v2 manifests and blobs', async () => {
    const tar = packTar({ 'lib/apk/db/installed': 'P:openssl\nV:1.1.1w\n\n' });
    const gz = gzipSync(tar);
    const fetchFn = vi.fn(async (url: string | URL, init?: RequestInit) => {
      const href = String(url);
      if (href.startsWith('https://quay.io/v2/auth')) {
        expect(href).toBe(AUTH);
        expect(init?.method).toBe('GET');
        const auth = (init?.headers as Record<string, string>).authorization;
        expect(auth).toBe(`Bearer ${TOKEN}`);
        return jsonResponse({ token: 'registry-token' });
      }
      expect(href.startsWith(`https://${HOST}/`)).toBe(true);
      if (href.includes('/manifests/')) {
        expect((init?.headers as Record<string, string>).authorization).toBe('Bearer registry-token');
        return jsonResponse(imageManifest());
      }
      if (href.includes('/blobs/')) return new Response(gz, { status: 200 });
      throw new Error(`unexpected url ${href}`);
    });

    const registry = new QuayRegistry(fetchFn as unknown as typeof fetch);
    const pulled = await registry.pull(REF, TOKEN, () => true);
    expect(pulled.layers).toHaveLength(1);
    expect(pulled.layers[0]?.digest).toBe(LAYER);
    expect(pulled.layers[0]?.files.has('lib/apk/db/installed')).toBe(true);
    expect(fetchFn.mock.calls.every((c) => String(c[0]).startsWith(`https://${HOST}/`))).toBe(true);
    expect(fetchFn.mock.calls.some((c) => String(c[0]).includes('/api/v1/'))).toBe(false);
    expect(fetchFn.mock.calls.some((c) => String(c[0]).includes('cdn.quay.io'))).toBe(false);
    expect(fetchFn.mock.calls.some((c) => String(c[0]).includes('ghcr.io'))).toBe(false);
    expect(fetchFn.mock.calls.some((c) => String(c[0]).includes('cloudflare'))).toBe(false);
  });

  it('follows a same-host blob redirect with the registry bearer', async () => {
    const tar = packTar({ 'lib/apk/db/installed': 'P:openssl\nV:1.1.1w\n\n' });
    const gz = gzipSync(tar);
    const next = `https://${HOST}/v2/acme/payments-api/blobs/${LAYER}?sig=1`;
    const fetchFn = vi.fn(async (url: string | URL, init?: RequestInit) => {
      const href = String(url);
      if (href.startsWith('https://quay.io/v2/auth')) return jsonResponse({ token: 'registry-token' });
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

    const registry = new QuayRegistry(fetchFn as unknown as typeof fetch);
    const pulled = await registry.pull(REF, TOKEN, () => true);
    expect(pulled.layers).toHaveLength(1);
  });

  it('refuses a CDN or suffix-confused blob redirect', async () => {
    const fetchFn = vi.fn(async (url: string | URL) => {
      const href = String(url);
      if (href.startsWith('https://quay.io/v2/auth')) return jsonResponse({ token: 'registry-token' });
      if (href.includes('/manifests/')) return jsonResponse(imageManifest());
      if (href.includes('/blobs/')) {
        return new Response(null, {
          status: 302,
          headers: { location: 'https://cdn.quay.io/v2/acme/payments-api/blobs/sha256/ab' },
        });
      }
      throw new Error(`unexpected url ${href}`);
    });
    await expect(
      new QuayRegistry(fetchFn as unknown as typeof fetch).pull(REF, TOKEN, () => true),
    ).rejects.toThrow(/quay\.io|redirect host/);
  });

  it('refuses a self-hosted or other-registry blob redirect', async () => {
    const fetchFn = vi.fn(async (url: string | URL) => {
      const href = String(url);
      if (href.startsWith('https://quay.io/v2/auth')) return jsonResponse({ token: 'registry-token' });
      if (href.includes('/manifests/')) return jsonResponse(imageManifest());
      if (href.includes('/blobs/')) {
        return new Response(null, {
          status: 302,
          headers: { location: 'https://quay.acme.example/v2/acme/payments-api/blobs/sha256:ab' },
        });
      }
      throw new Error(`unexpected url ${href}`);
    });
    await expect(
      new QuayRegistry(fetchFn as unknown as typeof fetch).pull(REF, TOKEN, () => true),
    ).rejects.toThrow(/quay\.io|redirect host/);
  });

  it('fails closed when token exchange or the blob GET is not ok', async () => {
    const denied = vi.fn(async () => new Response('nope', { status: 403 }));
    await expect(
      new QuayRegistry(denied as unknown as typeof fetch).pull(REF, TOKEN, () => true),
    ).rejects.toThrow(/token/);

    const fetchFn = vi.fn(async (url: string | URL) => {
      const href = String(url);
      if (href.startsWith('https://quay.io/v2/auth')) return jsonResponse({ token: 'registry-token' });
      if (href.includes('/manifests/')) return jsonResponse(imageManifest());
      return new Response('nope', { status: 502 });
    });
    await expect(
      new QuayRegistry(fetchFn as unknown as typeof fetch).pull(REF, TOKEN, () => true),
    ).rejects.toThrow(ContainerPullError);
  });

  it('throws when the deadline fires mid-pull', async () => {
    let calls = 0;
    const fetchFn = vi.fn(async (url: string | URL) => {
      const href = String(url);
      if (href.startsWith('https://quay.io/v2/auth')) return jsonResponse({ token: 't' });
      if (href.includes('/manifests/')) return jsonResponse(imageManifest());
      return new Response(gzipSync(packTar({ 'etc/os-release': 'ID=alpine\n' })), { status: 200 });
    });
    await expect(
      new QuayRegistry(fetchFn as unknown as typeof fetch).pull(REF, TOKEN, () => {
        calls += 1;
        return calls < 2;
      }),
    ).rejects.toThrow(/deadline/);
  });

  it('fails closed when the image manifest omits layers', async () => {
    const fetchFn = vi.fn(async (url: string | URL) => {
      const href = String(url);
      if (href.startsWith('https://quay.io/v2/auth')) return jsonResponse({ token: 'registry-token' });
      return jsonResponse({ schemaVersion: 2, mediaType: 'application/vnd.oci.image.manifest.v1+json' });
    });
    await expect(
      new QuayRegistry(fetchFn as unknown as typeof fetch).pull(REF, TOKEN, () => true),
    ).rejects.toThrow(/missing layers/);
  });
});
