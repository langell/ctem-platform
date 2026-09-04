import { afterEach, describe, expect, it, vi } from 'vitest';
import { gzipSync } from 'node:zlib';
import { GhcrRegistry, ContainerPullError } from './registry';
import { packTar } from './test-tar';

const DIGEST = `sha256:${'a'.repeat(64)}`;
const LAYER = `sha256:${'b'.repeat(64)}`;
const CONFIG = `sha256:${'c'.repeat(64)}`;

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

describe('GhcrRegistry.pull', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('pulls a mocked ghcr.io manifest and gzip layer without a live registry', async () => {
    const tar = packTar({ 'lib/apk/db/installed': 'P:openssl\nV:1.1.1w\n\n' });
    const gz = gzipSync(tar);
    const fetchFn = vi.fn(async (url: string | URL) => {
      const href = String(url);
      expect(href.startsWith('https://ghcr.io/')).toBe(true);
      if (href.includes('/token')) return jsonResponse({ token: 'registry-token' });
      if (href.includes('/manifests/')) return jsonResponse(imageManifest());
      if (href.includes('/blobs/')) return new Response(gz, { status: 200 });
      throw new Error(`unexpected url ${href}`);
    });

    const registry = new GhcrRegistry(fetchFn as unknown as typeof fetch);
    const pulled = await registry.pull(
      { owner: 'acme', name: 'payments-api', digest: DIGEST },
      'ghp_test',
      () => true,
    );
    expect(pulled.layers).toHaveLength(1);
    expect(pulled.layers[0]?.digest).toBe(LAYER);
    expect(pulled.layers[0]?.files.has('lib/apk/db/installed')).toBe(true);
    expect(fetchFn.mock.calls.every((c) => String(c[0]).startsWith('https://ghcr.io/'))).toBe(true);
  });

  it('fails closed when the blob GET is not ok', async () => {
    const fetchFn = vi.fn(async (url: string | URL) => {
      const href = String(url);
      if (href.includes('/token')) return jsonResponse({ token: 'registry-token' });
      if (href.includes('/manifests/')) return jsonResponse(imageManifest());
      return new Response('nope', { status: 502 });
    });
    const registry = new GhcrRegistry(fetchFn as unknown as typeof fetch);
    await expect(
      registry.pull({ owner: 'acme', name: 'app', digest: DIGEST }, 'ghp_test', () => true),
    ).rejects.toThrow(ContainerPullError);
  });

  it('throws when the deadline fires mid-pull', async () => {
    let calls = 0;
    const fetchFn = vi.fn(async (url: string | URL) => {
      const href = String(url);
      if (href.includes('/token')) return jsonResponse({ token: 't' });
      if (href.includes('/manifests/')) return jsonResponse(imageManifest());
      return new Response(gzipSync(packTar({ 'etc/os-release': 'ID=alpine\n' })), { status: 200 });
    });
    const registry = new GhcrRegistry(fetchFn as unknown as typeof fetch);
    await expect(
      registry.pull({ owner: 'acme', name: 'app', digest: DIGEST }, 'ghp_test', () => {
        calls += 1;
        return calls < 2;
      }),
    ).rejects.toThrow(/deadline/);
  });
});
