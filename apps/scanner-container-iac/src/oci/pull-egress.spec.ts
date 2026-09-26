import { gzipSync } from 'node:zlib';
import { randomUUID } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { ScanContext } from '@ctem/scanner-sdk';
import {
  CircuitOpenError,
  DEFAULT_CIRCUIT_BREAKER_CONFIG,
  InternalHttpPolicy,
  type CircuitBreakerConfig,
} from '@ctem/resilience';
import { ContainerScanError, ContainerScanner } from '../container.scanner';
import { allowlistedGhcrUrl, GHCR_BLOB_CDN_HOST } from '../container.egress';
import { GhcrRegistry, ContainerPullError, MAX_IMAGE_LAYERS } from './registry';
import { QuayRegistry } from './quay.registry';
import {
  EGRESS_ACR_REGISTRY,
  EGRESS_DOCKERHUB_REGISTRY,
  EGRESS_ECR_REGISTRY,
  EGRESS_GCR_REGISTRY,
  EGRESS_GHCR_REGISTRY,
  EGRESS_QUAY_REGISTRY,
  resetRegistryPullPolicy,
  useRegistryPullPolicy,
  type RegistryEgressCircuit,
} from './pull-egress';
import {
  decompressLayer,
  LayerUnpackError,
  MAX_INVENTORY_FILE_BYTES,
  MAX_LAYER_BYTES,
} from './tar';
import { packTar, tarHeaderOnly } from './test-tar';

const DIGEST = `sha256:${'a'.repeat(64)}`;
const LAYER = `sha256:${'b'.repeat(64)}`;
const CONFIG = `sha256:${'c'.repeat(64)}`;
const GHCR_REF = { owner: 'acme', name: 'payments-api', digest: DIGEST };
const QUAY_REF = {
  kind: 'quay' as const,
  namespace: 'acme',
  repository: 'payments-api',
  digest: DIGEST,
};
const QUAY_TOKEN = 'quay_test_token';

function fastPolicy(overrides: Partial<CircuitBreakerConfig> = {}): InternalHttpPolicy {
  return new InternalHttpPolicy(
    {
      ...DEFAULT_CIRCUIT_BREAKER_CONFIG,
      failureThreshold: 2,
      maxAttempts: 3,
      baseDelayMs: 1,
      timeoutMs: 1_000,
      ...overrides,
    },
    { sleep: async () => undefined, random: () => 0 },
  );
}

function jsonResponse(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });
}

function imageManifest(
  layers = [
    {
      mediaType: 'application/vnd.oci.image.layer.v1.tar+gzip',
      digest: LAYER,
      size: 10,
    },
  ],
) {
  return {
    schemaVersion: 2,
    mediaType: 'application/vnd.oci.image.manifest.v1+json',
    config: { mediaType: 'application/vnd.oci.image.config.v1+json', digest: CONFIG, size: 2 },
    layers,
  };
}

function layerGzip(
  files: Record<string, string> = { 'lib/apk/db/installed': 'P:openssl\nV:1.1.1w\n\n' },
): Buffer {
  return gzipSync(packTar(files));
}

function ghcrFetch(gz: Buffer = layerGzip()) {
  return vi.fn(async (url: string | URL, init?: RequestInit) => {
    const href = String(url);
    if (href.includes('/token')) return jsonResponse({ token: 'registry-token' });
    if (href.includes('/manifests/')) return jsonResponse(imageManifest());
    if (href.includes('/blobs/')) return new Response(gz, { status: 200 });
    throw new Error(`unexpected url ${href} ${init?.method ?? ''}`);
  });
}

function quayFetch(gz: Buffer = layerGzip()) {
  return vi.fn(async (url: string | URL) => {
    const href = String(url);
    if (href.startsWith('https://quay.io/v2/auth'))
      return jsonResponse({ token: 'registry-token' });
    if (href.includes('/manifests/')) return jsonResponse(imageManifest());
    if (href.includes('/blobs/')) return new Response(gz, { status: 200 });
    throw new Error(`unexpected url ${href}`);
  });
}

async function openCircuit(
  policy: InternalHttpPolicy,
  circuit: RegistryEgressCircuit,
): Promise<void> {
  await policy.execute(circuit, async () => new Response('down', { status: 500 }));
}

function scanCtx(): ScanContext {
  return {
    job: {
      jobId: randomUUID(),
      scanId: randomUUID(),
      orgId: randomUUID(),
      scannerType: 'container',
      assetId: randomUUID(),
      target: {
        kind: 'container_image',
        externalKey: `ghcr:acme/payments-api@${DIGEST}`,
        owner: 'acme',
        package: 'payments-api',
        digest: DIGEST,
        visibility: 'public',
      },
      credentialRef: null,
      options: {},
      attempt: 1,
      deadlineAt: new Date(Date.now() + 60_000),
      traceId: 'test',
    },
    workDir: '/tmp',
    checkDeadline: () => true,
    log: () => undefined,
  };
}

function scanner(registry: GhcrRegistry): ContainerScanner {
  const unused = { pull: vi.fn() };
  return new ContainerScanner(
    { match: vi.fn(), warmCache: vi.fn() } as never,
    registry,
    unused as never,
    unused as never,
    unused as never,
    unused as never,
    unused as never,
  );
}

beforeEach(() => {
  useRegistryPullPolicy(fastPolicy());
});

afterEach(() => {
  resetRegistryPullPolicy();
});

describe('registry pull egress circuit breaker', () => {
  it('open ghcr circuit fails the pull without fetch; other families still pull', async () => {
    const policy = fastPolicy({ failureThreshold: 1, maxAttempts: 1 });
    useRegistryPullPolicy(policy);
    for (const circuit of [
      EGRESS_ECR_REGISTRY,
      EGRESS_GCR_REGISTRY,
      EGRESS_ACR_REGISTRY,
      EGRESS_DOCKERHUB_REGISTRY,
    ]) {
      await openCircuit(policy, circuit);
    }

    const ghcrWhileOthersOpen = ghcrFetch();
    const pulled = await new GhcrRegistry(ghcrWhileOthersOpen as unknown as typeof fetch).pull(
      GHCR_REF,
      'ghp_test',
      () => true,
    );
    expect(pulled.layers).toHaveLength(1);
    expect(ghcrWhileOthersOpen).toHaveBeenCalled();

    await openCircuit(policy, EGRESS_GHCR_REGISTRY);
    const ghcrFetchBlocked = ghcrFetch();
    await expect(
      new GhcrRegistry(ghcrFetchBlocked as unknown as typeof fetch).pull(
        GHCR_REF,
        'ghp_test',
        () => true,
      ),
    ).rejects.toBeInstanceOf(CircuitOpenError);
    expect(ghcrFetchBlocked).not.toHaveBeenCalled();

    const quayFetchOk = quayFetch();
    const quayPulled = await new QuayRegistry(quayFetchOk as unknown as typeof fetch).pull(
      QUAY_REF,
      QUAY_TOKEN,
      () => true,
    );
    expect(quayPulled.layers).toHaveLength(1);
    expect(quayFetchOk).toHaveBeenCalled();

    const quayBlocked = quayFetch();
    await openCircuit(policy, EGRESS_QUAY_REGISTRY);
    await expect(
      new QuayRegistry(quayBlocked as unknown as typeof fetch).pull(
        QUAY_REF,
        QUAY_TOKEN,
        () => true,
      ),
    ).rejects.toThrow(/circuit open/);
    expect(quayBlocked).not.toHaveBeenCalled();
  });

  it('retries a 503 within budget and then pulls the layer', async () => {
    useRegistryPullPolicy(fastPolicy({ maxAttempts: 3 }));
    const gz = layerGzip();
    const seen = new Map<string, number>();
    const fetchFn = vi.fn(async (url: string | URL) => {
      const href = String(url);
      const key = href.includes('/token')
        ? 'token'
        : href.includes('/manifests/')
          ? 'manifest'
          : 'blob';
      const n = (seen.get(key) ?? 0) + 1;
      seen.set(key, n);
      if (n === 1) return new Response('unavailable', { status: 503 });
      if (key === 'token') return jsonResponse({ token: 'registry-token' });
      if (key === 'manifest') return jsonResponse(imageManifest());
      return new Response(gz, { status: 200 });
    });

    const pulled = await new GhcrRegistry(fetchFn as unknown as typeof fetch).pull(
      GHCR_REF,
      'ghp_test',
      () => true,
    );
    expect(pulled.layers).toHaveLength(1);
    expect(pulled.layers[0]?.files.has('lib/apk/db/installed')).toBe(true);
    expect(fetchFn).toHaveBeenCalledTimes(6);
    expect(seen.get('token')).toBe(2);
    expect(seen.get('manifest')).toBe(2);
    expect(seen.get('blob')).toBe(2);
  });

  it('does not retry 4xx and does not open the circuit', async () => {
    useRegistryPullPolicy(fastPolicy({ failureThreshold: 1, maxAttempts: 3 }));
    const denied = vi.fn(async () => new Response('no', { status: 401 }));
    await expect(
      new GhcrRegistry(denied as unknown as typeof fetch).pull(GHCR_REF, 'ghp_test', () => true),
    ).rejects.toThrow(/401/);
    expect(denied).toHaveBeenCalledTimes(1);

    const blobDenied = vi.fn(async (url: string | URL) => {
      const href = String(url);
      if (href.includes('/token')) return jsonResponse({ token: 'registry-token' });
      if (href.includes('/manifests/')) return jsonResponse(imageManifest());
      return new Response('missing', { status: 404 });
    });
    await expect(
      new GhcrRegistry(blobDenied as unknown as typeof fetch).pull(
        GHCR_REF,
        'ghp_test',
        () => true,
      ),
    ).rejects.toThrow(ContainerPullError);
    expect(blobDenied).toHaveBeenCalledTimes(3);

    const recovered = ghcrFetch();
    const pulled = await new GhcrRegistry(recovered as unknown as typeof fetch).pull(
      GHCR_REF,
      'ghp_test',
      () => true,
    );
    expect(pulled.layers).toHaveLength(1);
    expect(recovered).toHaveBeenCalled();
  });

  it('keeps allowlist refusal off the circuit and still refuses an off-allowlist redirect', async () => {
    useRegistryPullPolicy(fastPolicy({ failureThreshold: 1, maxAttempts: 1 }));
    const untouched = vi.fn();
    expect(() =>
      allowlistedGhcrUrl('https://registry.evil/v2/acme/app/manifests/sha256:ab'),
    ).toThrow(/ghcr\.io/);
    expect(untouched).not.toHaveBeenCalled();

    const cdn = vi.fn(async (url: string | URL) => {
      const href = String(url);
      if (href.startsWith('https://quay.io/v2/auth'))
        return jsonResponse({ token: 'registry-token' });
      if (href.includes('/manifests/')) return jsonResponse(imageManifest());
      if (href.includes('/blobs/') && href.startsWith('https://quay.io/')) {
        return new Response(null, {
          status: 302,
          headers: { location: 'https://cdn.quay.io/v2/acme/payments-api/blobs/sha256/ab' },
        });
      }
      throw new Error(`unexpected url ${href}`);
    });
    await expect(
      new QuayRegistry(cdn as unknown as typeof fetch).pull(QUAY_REF, QUAY_TOKEN, () => true),
    ).rejects.toThrow(/quay\.io|redirect host/);
    expect(cdn.mock.calls.some((call) => String(call[0]).includes('cdn.quay.io'))).toBe(false);

    const ghcrCdn = vi.fn(async (url: string | URL) => {
      const href = String(url);
      if (href.includes('/token')) return jsonResponse({ token: 'registry-token' });
      if (href.includes('/manifests/')) return jsonResponse(imageManifest());
      if (href.startsWith('https://ghcr.io/') && href.includes('/blobs/')) {
        return new Response(null, {
          status: 302,
          headers: { location: 'https://evil.example/layer' },
        });
      }
      throw new Error(`unexpected url ${href}`);
    });
    await expect(
      new GhcrRegistry(ghcrCdn as unknown as typeof fetch).pull(GHCR_REF, 'ghp_test', () => true),
    ).rejects.toThrow(/redirect host/);
    expect(ghcrCdn.mock.calls.some((call) => String(call[0]).includes('evil.example'))).toBe(false);

    const recovered = quayFetch();
    const pulled = await new QuayRegistry(recovered as unknown as typeof fetch).pull(
      QUAY_REF,
      QUAY_TOKEN,
      () => true,
    );
    expect(pulled.layers).toHaveLength(1);
  });

  it('still follows the allowlisted GHCR blob CDN and does not attach the bearer', async () => {
    const gz = layerGzip();
    const next = `https://${GHCR_BLOB_CDN_HOST}/ghcr1/blobs/${LAYER}`;
    const fetchFn = vi.fn(async (url: string | URL, init?: RequestInit) => {
      const href = String(url);
      if (href.includes('/token')) return jsonResponse({ token: 'registry-token' });
      if (href.includes('/manifests/')) return jsonResponse(imageManifest());
      if (href.startsWith('https://ghcr.io/') && href.includes('/blobs/')) {
        return new Response(null, { status: 302, headers: { location: next } });
      }
      if (href === next) {
        const headers = init?.headers as Record<string, string>;
        expect(headers.authorization).toBeUndefined();
        return new Response(gz, { status: 200 });
      }
      throw new Error(`unexpected url ${href}`);
    });
    const pulled = await new GhcrRegistry(fetchFn as unknown as typeof fetch).pull(
      GHCR_REF,
      'ghp_test',
      () => true,
    );
    expect(pulled.layers).toHaveLength(1);
    expect(fetchFn.mock.calls.some((call) => String(call[0]) === next)).toBe(true);
  });

  it('fails the container job when the circuit is open or the retry budget is exhausted', async () => {
    const openPolicy = fastPolicy({ failureThreshold: 1, maxAttempts: 1 });
    useRegistryPullPolicy(openPolicy);
    await openCircuit(openPolicy, EGRESS_GHCR_REGISTRY);
    const blocked = ghcrFetch();
    const jobError = await scanner(new GhcrRegistry(blocked as unknown as typeof fetch))
      .execute(scanCtx())
      .then(
        () => Promise.reject(new Error('expected the container job to fail')),
        (err: unknown) => err,
      );
    expect(jobError).toBeInstanceOf(ContainerScanError);
    expect((jobError as Error).message).toMatch(/circuit open: egress:ghcr-registry/);
    expect((jobError as Error).message).toMatch(/refusing incomplete/);
    expect(blocked).not.toHaveBeenCalled();

    useRegistryPullPolicy(fastPolicy({ maxAttempts: 2, failureThreshold: 5 }));
    const flapping = vi.fn(async () => new Response('unavailable', { status: 503 }));
    await expect(
      scanner(new GhcrRegistry(flapping as unknown as typeof fetch)).execute(scanCtx()),
    ).rejects.toThrow(ContainerPullError);
    expect(flapping).toHaveBeenCalledTimes(2);
  });

  it('still fails closed on layer-count, deadline, truncated, and size caps', async () => {
    const tooMany = Array.from({ length: MAX_IMAGE_LAYERS + 1 }, (_, i) => ({
      mediaType: 'application/vnd.oci.image.layer.v1.tar+gzip',
      digest: `sha256:${(i + 1).toString(16).padStart(64, '0')}`,
      size: 1,
    }));
    const countFetch = vi.fn(async (url: string | URL) => {
      const href = String(url);
      if (href.includes('/token')) return jsonResponse({ token: 'registry-token' });
      if (href.includes('/manifests/')) return jsonResponse(imageManifest(tooMany));
      throw new Error(`blob fetch should not run ${href}`);
    });
    await expect(
      new GhcrRegistry(countFetch as unknown as typeof fetch).pull(
        GHCR_REF,
        'ghp_test',
        () => true,
      ),
    ).rejects.toThrow(/incomplete inventory/);
    expect(countFetch.mock.calls.some((call) => String(call[0]).includes('/blobs/'))).toBe(false);

    let checks = 0;
    const deadlineFetch = vi.fn(async (url: string | URL) => {
      const href = String(url);
      if (href.includes('/token')) return jsonResponse({ token: 't' });
      if (href.includes('/manifests/')) return jsonResponse(imageManifest());
      return new Response(layerGzip({ 'etc/os-release': 'ID=alpine\n' }), { status: 200 });
    });
    await expect(
      new GhcrRegistry(deadlineFetch as unknown as typeof fetch).pull(GHCR_REF, 'ghp_test', () => {
        checks += 1;
        return checks < 2;
      }),
    ).rejects.toThrow(/deadline/);

    const truncated = vi.fn(async (url: string | URL) => {
      const href = String(url);
      if (href.includes('/token')) return jsonResponse({ token: 'registry-token' });
      if (href.includes('/manifests/')) {
        return jsonResponse(
          imageManifest([
            {
              mediaType: 'application/vnd.oci.image.layer.v1.tar',
              digest: LAYER,
              size: 100,
            },
          ]),
        );
      }
      return new Response(tarHeaderOnly('lib/apk/db/installed', 100), { status: 200 });
    });
    await expect(
      new GhcrRegistry(truncated as unknown as typeof fetch).pull(GHCR_REF, 'ghp_test', () => true),
    ).rejects.toThrow(/Truncated tar|incomplete/);

    const big = 'P:openssl\n'.padEnd(MAX_INVENTORY_FILE_BYTES + 1, 'x');
    const oversized = vi.fn(async (url: string | URL) => {
      const href = String(url);
      if (href.includes('/token')) return jsonResponse({ token: 'registry-token' });
      if (href.includes('/manifests/')) {
        return jsonResponse(
          imageManifest([
            {
              mediaType: 'application/vnd.oci.image.layer.v1.tar',
              digest: LAYER,
              size: big.length,
            },
          ]),
        );
      }
      return new Response(packTar({ 'lib/apk/db/installed': big }), { status: 200 });
    });
    await expect(
      new GhcrRegistry(oversized as unknown as typeof fetch).pull(GHCR_REF, 'ghp_test', () => true),
    ).rejects.toBeInstanceOf(LayerUnpackError);

    const fat = new Proxy(Buffer.alloc(1), {
      get(target, prop, receiver) {
        if (prop === 'length') return MAX_LAYER_BYTES + 1;
        const value = Reflect.get(target, prop, receiver) as unknown;
        return typeof value === 'function'
          ? (value as (...args: unknown[]) => unknown).bind(target)
          : value;
      },
    }) as Buffer;
    expect(() => decompressLayer(fat, 'application/vnd.oci.image.layer.v1.tar')).toThrow(
      /exceeds cap/,
    );
  });
});
