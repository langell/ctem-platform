import { afterEach, describe, expect, it, vi } from 'vitest';
import { gzipSync } from 'node:zlib';
import { EcrRegistry } from './ecr.registry';
import { ContainerPullError } from './registry';
import { packTar } from './test-tar';

const DIGEST = `sha256:${'a'.repeat(64)}`;
const LAYER = `sha256:${'b'.repeat(64)}`;
const CONFIG = `sha256:${'c'.repeat(64)}`;
const ACCOUNT = '123456789012';
const REGION = 'us-east-1';
const REGISTRY = `${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com`;
const CREDS = { accessKeyId: 'AKIATEST', secretAccessKey: 'secret' };
const REF = {
  kind: 'ecr' as const,
  accountId: ACCOUNT,
  repositoryName: 'payments-api',
  digest: DIGEST,
  region: REGION,
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

function authResponse() {
  return {
    authorizationData: [
      {
        authorizationToken: Buffer.from('AWS:registry-password').toString('base64'),
        proxyEndpoint: 'https://evil.example',
      },
    ],
  };
}

describe('EcrRegistry.pull', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('pulls a mocked ECR digest via GetAuthorizationToken + dkr.ecr, ignoring proxyEndpoint', async () => {
    const tar = packTar({ 'lib/apk/db/installed': 'P:openssl\nV:1.1.1w\n\n' });
    const gz = gzipSync(tar);
    const fetchFn = vi.fn(async (url: string | URL, init?: RequestInit) => {
      const href = String(url);
      if (href === 'https://api.ecr.us-east-1.amazonaws.com/') {
        expect(init?.method).toBe('POST');
        const headers = init?.headers as Record<string, string>;
        expect(headers.authorization).toMatch(/^AWS4-HMAC-SHA256 /);
        expect(headers['x-amz-target']).toContain('GetAuthorizationToken');
        expect(String(init?.body)).toContain(ACCOUNT);
        return jsonResponse(authResponse());
      }
      expect(href.startsWith(`https://${REGISTRY}/`)).toBe(true);
      if (href.includes('/manifests/')) return jsonResponse(imageManifest());
      if (href.includes('/blobs/')) return new Response(gz, { status: 200 });
      throw new Error(`unexpected url ${href}`);
    });

    const registry = new EcrRegistry(fetchFn as unknown as typeof fetch);
    const pulled = await registry.pull(REF, CREDS, () => true);
    expect(pulled.layers).toHaveLength(1);
    expect(pulled.layers[0]?.digest).toBe(LAYER);
    expect(pulled.layers[0]?.files.has('lib/apk/db/installed')).toBe(true);
    expect(
      fetchFn.mock.calls.every((c) => {
        const href = String(c[0]);
        return href.startsWith('https://api.ecr.') || href.startsWith(`https://${REGISTRY}/`);
      }),
    ).toBe(true);
    expect(fetchFn.mock.calls.some((c) => String(c[0]).includes('evil.example'))).toBe(false);
    expect(fetchFn.mock.calls.some((c) => String(c[0]).includes('ghcr.io'))).toBe(false);
  });

  it('follows a regional S3 blob redirect without attaching the ECR token', async () => {
    const tar = packTar({ 'lib/apk/db/installed': 'P:openssl\nV:1.1.1w\n\n' });
    const gz = gzipSync(tar);
    const s3 = 'https://prod-us-east-1-starport-layer-bucket.s3.us-east-1.amazonaws.com/blob?sig=1';
    const fetchFn = vi.fn(async (url: string | URL, init?: RequestInit) => {
      const href = String(url);
      if (href.startsWith('https://api.ecr.')) return jsonResponse(authResponse());
      if (href.includes('/manifests/')) return jsonResponse(imageManifest());
      if (href.includes('/blobs/')) {
        return new Response(null, { status: 302, headers: { location: s3 } });
      }
      if (href.startsWith('https://prod-us-east-1-starport-layer-bucket.s3.us-east-1.amazonaws.com/')) {
        const headers = init?.headers as Record<string, string>;
        expect(headers.authorization).toBeUndefined();
        return new Response(gz, { status: 200 });
      }
      throw new Error(`unexpected url ${href}`);
    });

    const registry = new EcrRegistry(fetchFn as unknown as typeof fetch);
    const pulled = await registry.pull(REF, CREDS, () => true);
    expect(pulled.layers).toHaveLength(1);
  });

  it('fails closed when GetAuthorizationToken or the blob GET is not ok', async () => {
    const denied = vi.fn(async () => new Response('nope', { status: 403 }));
    await expect(
      new EcrRegistry(denied as unknown as typeof fetch).pull(REF, CREDS, () => true),
    ).rejects.toThrow(/GetAuthorizationToken returned 403/);

    const fetchFn = vi.fn(async (url: string | URL) => {
      const href = String(url);
      if (href.startsWith('https://api.ecr.')) return jsonResponse(authResponse());
      if (href.includes('/manifests/')) return jsonResponse(imageManifest());
      return new Response('nope', { status: 502 });
    });
    await expect(
      new EcrRegistry(fetchFn as unknown as typeof fetch).pull(REF, CREDS, () => true),
    ).rejects.toThrow(ContainerPullError);
  });

  it('throws when the deadline fires mid-pull', async () => {
    let calls = 0;
    const fetchFn = vi.fn(async (url: string | URL) => {
      const href = String(url);
      if (href.startsWith('https://api.ecr.')) return jsonResponse(authResponse());
      if (href.includes('/manifests/')) return jsonResponse(imageManifest());
      return new Response(gzipSync(packTar({ 'etc/os-release': 'ID=alpine\n' })), { status: 200 });
    });
    await expect(
      new EcrRegistry(fetchFn as unknown as typeof fetch).pull(REF, CREDS, () => {
        calls += 1;
        return calls < 2;
      }),
    ).rejects.toThrow(/deadline/);
  });

  it('fails closed when the image manifest omits layers', async () => {
    const fetchFn = vi.fn(async (url: string | URL) => {
      const href = String(url);
      if (href.startsWith('https://api.ecr.')) return jsonResponse(authResponse());
      return jsonResponse({ schemaVersion: 2, mediaType: 'application/vnd.oci.image.manifest.v1+json' });
    });
    await expect(
      new EcrRegistry(fetchFn as unknown as typeof fetch).pull(REF, CREDS, () => true),
    ).rejects.toThrow(/missing layers/);
  });
});
