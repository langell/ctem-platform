import { afterEach, describe, expect, it, vi } from 'vitest';
import { gzipSync } from 'node:zlib';
import { generateKeyPairSync } from 'node:crypto';
import { GcrRegistry } from './gcr.registry';
import { ContainerPullError } from './registry';
import { packTar } from './test-tar';

const DIGEST = `sha256:${'a'.repeat(64)}`;
const LAYER = `sha256:${'b'.repeat(64)}`;
const CONFIG = `sha256:${'c'.repeat(64)}`;
const PROJECT = 'acme-prod';
const LOCATION = 'us-central1';
const REGISTRY = `${LOCATION}-docker.pkg.dev`;
const gcpPem = generateKeyPairSync('rsa', { modulusLength: 2048 })
  .privateKey.export({ type: 'pkcs8', format: 'pem' })
  .toString();
const CREDS = {
  clientEmail: 'ctem-scanner@acme-prod.iam.gserviceaccount.com',
  privateKey: gcpPem,
};
const REF = {
  kind: 'gcr' as const,
  projectId: PROJECT,
  location: LOCATION,
  repository: 'payments-api',
  image: 'web',
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

describe('GcrRegistry.pull', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('pulls a mocked AR digest via oauth2.googleapis.com + pinned docker.pkg.dev', async () => {
    const tar = packTar({ 'lib/apk/db/installed': 'P:openssl\nV:1.1.1w\n\n' });
    const gz = gzipSync(tar);
    const fetchFn = vi.fn(async (url: string | URL, init?: RequestInit) => {
      const href = String(url);
      if (href === 'https://oauth2.googleapis.com/token') {
        expect(init?.method).toBe('POST');
        expect(String(init?.body)).toContain('assertion=');
        return jsonResponse({ access_token: 'ya29.test' });
      }
      expect(href.startsWith(`https://${REGISTRY}/`)).toBe(true);
      if (href.includes('/v2/token')) {
        expect((init?.headers as Record<string, string>).authorization).toBe('Bearer ya29.test');
        return jsonResponse({ token: 'registry-token' });
      }
      if (href.includes('/manifests/')) return jsonResponse(imageManifest());
      if (href.includes('/blobs/')) return new Response(gz, { status: 200 });
      throw new Error(`unexpected url ${href}`);
    });

    const registry = new GcrRegistry(fetchFn as unknown as typeof fetch);
    const pulled = await registry.pull(REF, CREDS, () => true);
    expect(pulled.layers).toHaveLength(1);
    expect(pulled.layers[0]?.digest).toBe(LAYER);
    expect(pulled.layers[0]?.files.has('lib/apk/db/installed')).toBe(true);
    expect(
      fetchFn.mock.calls.every((c) => {
        const href = String(c[0]);
        return href.startsWith('https://oauth2.googleapis.com/') || href.startsWith(`https://${REGISTRY}/`);
      }),
    ).toBe(true);
    expect(fetchFn.mock.calls.some((c) => String(c[0]).includes('pkg.dev.evil'))).toBe(false);
    expect(fetchFn.mock.calls.some((c) => String(c[0]).includes('ghcr.io'))).toBe(false);
    expect(fetchFn.mock.calls.some((c) => String(c[0]).includes('azurecr.io'))).toBe(false);
  });

  it('follows a path-style GCS blob redirect without attaching the AR token', async () => {
    const tar = packTar({ 'lib/apk/db/installed': 'P:openssl\nV:1.1.1w\n\n' });
    const gz = gzipSync(tar);
    const gcs = 'https://storage.googleapis.com/artifacts-acme/containers/images/blob?sig=1';
    const fetchFn = vi.fn(async (url: string | URL, init?: RequestInit) => {
      const href = String(url);
      if (href === 'https://oauth2.googleapis.com/token') return jsonResponse({ access_token: 'ya29.test' });
      if (href.includes('/v2/token')) return jsonResponse({ token: 'registry-token' });
      if (href.includes('/manifests/')) return jsonResponse(imageManifest());
      if (href.includes('/blobs/')) {
        return new Response(null, { status: 302, headers: { location: gcs } });
      }
      if (href.startsWith('https://storage.googleapis.com/')) {
        const headers = init?.headers as Record<string, string>;
        expect(headers.authorization).toBeUndefined();
        return new Response(gz, { status: 200 });
      }
      throw new Error(`unexpected url ${href}`);
    });

    const registry = new GcrRegistry(fetchFn as unknown as typeof fetch);
    const pulled = await registry.pull(REF, CREDS, () => true);
    expect(pulled.layers).toHaveLength(1);
  });

  it('refuses a suffix-confused pkg.dev blob redirect', async () => {
    const fetchFn = vi.fn(async (url: string | URL) => {
      const href = String(url);
      if (href === 'https://oauth2.googleapis.com/token') return jsonResponse({ access_token: 'ya29.test' });
      if (href.includes('/v2/token')) return jsonResponse({ token: 'registry-token' });
      if (href.includes('/manifests/')) return jsonResponse(imageManifest());
      if (href.includes('/blobs/')) {
        return new Response(null, {
          status: 302,
          headers: { location: 'https://us-central1-docker.pkg.dev.evil.example/blob' },
        });
      }
      throw new Error(`unexpected url ${href}`);
    });
    await expect(
      new GcrRegistry(fetchFn as unknown as typeof fetch).pull(REF, CREDS, () => true),
    ).rejects.toThrow(/pkg\.dev|redirect host/);
  });

  it('fails closed when Google token exchange or the blob GET is not ok', async () => {
    const denied = vi.fn(async () => new Response('nope', { status: 403 }));
    await expect(
      new GcrRegistry(denied as unknown as typeof fetch).pull(REF, CREDS, () => true),
    ).rejects.toThrow(/token/);

    const fetchFn = vi.fn(async (url: string | URL) => {
      const href = String(url);
      if (href === 'https://oauth2.googleapis.com/token') return jsonResponse({ access_token: 'ya29.test' });
      if (href.includes('/v2/token')) return jsonResponse({ token: 'registry-token' });
      if (href.includes('/manifests/')) return jsonResponse(imageManifest());
      return new Response('nope', { status: 502 });
    });
    await expect(
      new GcrRegistry(fetchFn as unknown as typeof fetch).pull(REF, CREDS, () => true),
    ).rejects.toThrow(ContainerPullError);
  });

  it('throws when the deadline fires mid-pull', async () => {
    let calls = 0;
    const fetchFn = vi.fn(async (url: string | URL) => {
      const href = String(url);
      if (href === 'https://oauth2.googleapis.com/token') return jsonResponse({ access_token: 'ya29.test' });
      if (href.includes('/v2/token')) return jsonResponse({ token: 't' });
      if (href.includes('/manifests/')) return jsonResponse(imageManifest());
      return new Response(gzipSync(packTar({ 'etc/os-release': 'ID=alpine\n' })), { status: 200 });
    });
    await expect(
      new GcrRegistry(fetchFn as unknown as typeof fetch).pull(REF, CREDS, () => {
        calls += 1;
        return calls < 2;
      }),
    ).rejects.toThrow(/deadline/);
  });

  it('fails closed when the image manifest omits layers', async () => {
    const fetchFn = vi.fn(async (url: string | URL) => {
      const href = String(url);
      if (href === 'https://oauth2.googleapis.com/token') return jsonResponse({ access_token: 'ya29.test' });
      if (href.includes('/v2/token')) return jsonResponse({ token: 'registry-token' });
      return jsonResponse({ schemaVersion: 2, mediaType: 'application/vnd.oci.image.manifest.v1+json' });
    });
    await expect(
      new GcrRegistry(fetchFn as unknown as typeof fetch).pull(REF, CREDS, () => true),
    ).rejects.toThrow(/missing layers/);
  });
});
