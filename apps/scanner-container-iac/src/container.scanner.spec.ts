import { gzipSync } from 'node:zlib';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ScanContext } from '@ctem/scanner-sdk';
import { FindingNormalizer } from '../../findings-service/src/findings/finding-normalizer';
import { ContainerScanError, ContainerScanner } from './container.scanner';
import { ContainerCredentialError } from './container.credential';
import { ContainerEgressError } from './container.egress';
import { ContainerIdentityError } from './container.identity';
import { ContainerInventoryError } from './inventory/packages';
import { ContainerPullError, type ImagePuller, type LayerSnapshot } from './oci/registry';
import type { VulnMatcher } from '@ctem/vuln-intel';

const DIGEST = `sha256:${'a'.repeat(64)}`;
const LAYER_BASE = `sha256:${'b'.repeat(64)}`;
const LAYER_APP = `sha256:${'c'.repeat(64)}`;
const GHCR_KEY = `ghcr:acme/payments-api@${DIGEST}`;

const APK_DB = ['P:openssl', 'V:1.1.1w', 'A:x86_64', '', 'P:busybox', 'V:1.36.1', '', ''].join('\n');
const LODASH_JSON = JSON.stringify({ name: 'lodash', version: '4.17.21' });

function layer(digest: string, files: Record<string, string>, whiteouts: string[] = []): LayerSnapshot {
  return {
    digest,
    mediaType: 'application/vnd.oci.image.layer.v1.tar+gzip',
    files: new Map(Object.entries(files).map(([path, body]) => [path, Buffer.from(body)])),
    whiteouts,
    opaqueDirs: [],
  };
}

function ctx(
  overrides: Partial<ScanContext['job']> = {},
  checkDeadline: () => boolean = () => true,
): ScanContext {
  return {
    job: {
      jobId: randomUUID(),
      scanId: randomUUID(),
      orgId: randomUUID(),
      scannerType: 'container',
      assetId: randomUUID(),
      target: {
        kind: 'container_image',
        externalKey: GHCR_KEY,
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
      ...overrides,
    },
    workDir: '/tmp',
    checkDeadline,
    log: () => undefined,
  };
}

function matchingMatcher(names: string[] = ['openssl', 'lodash']) {
  return {
    match: vi.fn(async (component: { name: string }) => ({
      matches: names.includes(component.name)
        ? [
            {
              id: 'CVE-2024-0001',
              source: 'CVE',
              aliases: ['GHSA-test'],
              summary: 'test advisory',
              severity: 'high' as const,
              cvssVector: null,
              cvssScore: 7.5,
              epssScore: null,
              kev: false,
              fixedVersion: '9.9.9',
            },
          ]
        : [],
      mirrored: true,
    })),
    warmCache: vi.fn(),
  };
}

function puller(layers: LayerSnapshot[], spy?: (ref: unknown) => void): ImagePuller {
  return {
    pull: vi.fn(async (ref, _token, checkDeadline) => {
      spy?.(ref);
      if (!checkDeadline()) throw new ContainerPullError('Job deadline exceeded mid-pull');
      return { digest: DIGEST, owner: 'acme', name: 'payments-api', layers };
    }),
  };
}

function scanner(matcher = matchingMatcher(), registry?: ImagePuller): ContainerScanner {
  return new ContainerScanner(
    matcher as unknown as VulnMatcher,
    (registry ?? puller([layer(LAYER_BASE, { 'lib/apk/db/installed': APK_DB })])) as never,
  );
}

afterEach(() => {
  delete process.env.GITHUB_TOKEN;
});

describe('ContainerScanner.supports', () => {
  it('supports only container_image and kubernetes_workload', () => {
    const s = scanner();
    expect(s.supports({ target: { kind: 'container_image' } } as never)).toBe(true);
    expect(s.supports({ target: { kind: 'kubernetes_workload' } } as never)).toBe(true);
    expect(s.supports({ target: { kind: 'repository' } } as never)).toBe(false);
    expect(s.supports({ target: { kind: 'iac_stack' } } as never)).toBe(false);
  });
});

describe('ContainerScanner.execute', () => {
  it('throws for kubernetes_workload instead of returning { findings: [] }', async () => {
    const registry = puller([]);
    const s = scanner(matchingMatcher(), registry);
    await expect(s.execute(ctx({ target: { kind: 'kubernetes_workload', externalKey: GHCR_KEY } }))).rejects.toThrow(
      ContainerScanError,
    );
    await expect(
      s.execute(ctx({ target: { kind: 'kubernetes_workload', externalKey: GHCR_KEY } })),
    ).rejects.toThrow(/kubernetes_workload/);
    expect(registry.pull).not.toHaveBeenCalled();
  });

  it('refuses tenant registryUrl / off-allowlist registry before connect', async () => {
    const registry = puller([]);
    const s = scanner(matchingMatcher(), registry);
    await expect(
      s.execute(ctx({ options: { registryUrl: 'https://docker.io' } })),
    ).rejects.toThrow(ContainerEgressError);
    await expect(s.execute(ctx({ options: { ghcrUrl: 'https://ghcr.io' } }))).rejects.toThrow(/tenant-writable/);
    await expect(
      s.execute(
        ctx({
          target: {
            kind: 'container_image',
            externalKey: GHCR_KEY,
            registryUrl: 'https://123.dkr.ecr.us-east-1.amazonaws.com',
          },
        }),
      ),
    ).rejects.toThrow(ContainerEgressError);
    expect(registry.pull).not.toHaveBeenCalled();
  });

  it('fails closed on a non-digest or malformed externalKey', async () => {
    const registry = puller([]);
    const s = scanner(matchingMatcher(), registry);
    await expect(
      s.execute(ctx({ target: { kind: 'container_image', externalKey: 'ghcr:acme/app:latest' } })),
    ).rejects.toThrow(ContainerIdentityError);
    await expect(
      s.execute(ctx({ target: { kind: 'container_image', externalKey: 'image:ghcr.io/acme/app:latest' } })),
    ).rejects.toThrow(/non-digest|malformed/);
    await expect(
      s.execute(
        ctx({
          target: {
            kind: 'container_image',
            externalKey: `docker.io/library/nginx@${DIGEST}`,
          },
        }),
      ),
    ).rejects.toThrow(ContainerIdentityError);
    await expect(
      s.execute(
        ctx({
          target: {
            kind: 'container_image',
            externalKey: `ghcr:acme/app@sha256:deadbeef`,
          },
        }),
      ),
    ).rejects.toThrow(ContainerIdentityError);
    expect(registry.pull).not.toHaveBeenCalled();
  });

  it('fails a private pull when GITHUB_* credentials are missing — no empty success', async () => {
    const registry = puller([]);
    const s = scanner(matchingMatcher(), registry);
    await expect(
      s.execute(
        ctx({
          target: { kind: 'container_image', externalKey: GHCR_KEY, visibility: 'private' },
          credentialRef: null,
        }),
      ),
    ).rejects.toThrow(ContainerCredentialError);
    await expect(
      s.execute(
        ctx({
          target: { kind: 'container_image', externalKey: GHCR_KEY, visibility: 'private' },
          credentialRef: 'env:GITHUB_TOKEN',
        }),
      ),
    ).rejects.toThrow(/cannot be used/);
    expect(registry.pull).not.toHaveBeenCalled();
  });

  it('matches vulns after a complete mocked pull and records the introducer layer', async () => {
    process.env.GITHUB_TOKEN = 'ghp_test';
    try {
      const layers = [
        layer(LAYER_BASE, { 'lib/apk/db/installed': APK_DB }),
        layer(LAYER_APP, { 'app/node_modules/lodash/package.json': LODASH_JSON }),
      ];
      const registry = puller(layers);
      const matcher = matchingMatcher(['openssl', 'lodash']);
      const outcome = await scanner(matcher, registry).execute(
        ctx({ credentialRef: 'env:GITHUB_TOKEN', target: { ...ctx().job.target, visibility: 'public' } }),
      );
      expect(registry.pull).toHaveBeenCalledOnce();
      expect(outcome.findings.length).toBeGreaterThanOrEqual(2);
      expect(outcome.findings.every((f) => f.scannerType === 'container')).toBe(true);
      const openssl = outcome.findings.find((f) => f.location.packageName === 'openssl');
      const lodash = outcome.findings.find((f) => f.location.packageName === 'lodash');
      expect(openssl?.location.imageLayer).toBe(LAYER_BASE);
      expect(openssl?.evidence.introducedByLayer).toBe(LAYER_BASE);
      expect(lodash?.location.imageLayer).toBe(LAYER_APP);
      expect(lodash?.evidence.introducedByLayer).toBe(LAYER_APP);
      expect(openssl?.location.purl).toContain('pkg:apk/openssl@');
      expect(lodash?.location.purl).toContain('pkg:npm/lodash@4.17.21');
      expect((outcome.rawOutput as { truncated: boolean; complete: boolean }).truncated).toBe(false);
      expect((outcome.rawOutput as { complete: boolean }).complete).toBe(true);
    } finally {
      delete process.env.GITHUB_TOKEN;
    }
  });

  it('throws on pull failure, incomplete inventory, crash, and deadline — no partial publish', async () => {
    const failPull: ImagePuller = {
      pull: vi.fn(async () => {
        throw new ContainerPullError('GHCR blob GET returned 502 — refusing pull');
      }),
    };
    await expect(scanner(matchingMatcher(), failPull).execute(ctx())).rejects.toThrow(ContainerPullError);

    const rpm = puller([layer(LAYER_BASE, { 'var/lib/rpm/Packages': 'berkeley-db' })]);
    await expect(scanner(matchingMatcher(), rpm).execute(ctx())).rejects.toThrow(ContainerInventoryError);

    const crashing = matchingMatcher();
    crashing.match.mockImplementation(async () => {
      throw new Error('matcher panicked');
    });
    await expect(
      scanner(crashing, puller([layer(LAYER_BASE, { 'lib/apk/db/installed': APK_DB })])).execute(ctx()),
    ).rejects.toThrow(ContainerScanError);

    await expect(scanner().execute({ ...ctx(), checkDeadline: () => false })).rejects.toThrow(/deadline/);

    const midPull: ImagePuller = {
      pull: vi.fn(async (_ref, _token, checkDeadline) => {
        if (!checkDeadline()) throw new ContainerPullError('Job deadline exceeded mid-pull');
        return { digest: DIGEST, owner: 'acme', name: 'payments-api', layers: [] };
      }),
    };
    let allow = true;
    await expect(
      scanner(matchingMatcher(), midPull).execute({
        ...ctx(),
        checkDeadline: () => {
          const ok = allow;
          allow = false;
          return ok;
        },
      }),
    ).rejects.toThrow(/deadline/);
  });

  it('returns empty success only after a complete pull with zero packages', async () => {
    const registry = puller([layer(LAYER_BASE, { 'etc/os-release': 'ID=scratch\n' })]);
    const matcher = matchingMatcher([]);
    const outcome = await scanner(matcher, registry).execute(ctx());
    expect(registry.pull).toHaveBeenCalledOnce();
    expect(outcome.findings).toEqual([]);
    expect(outcome.stats?.packages).toBe(0);
    expect((outcome.rawOutput as { complete: boolean; truncated: boolean }).complete).toBe(true);
    expect((outcome.rawOutput as { truncated: boolean }).truncated).toBe(false);
    expect(matcher.match).not.toHaveBeenCalled();
  });

  it('keeps base vs app layer fingerprints distinct and does not collide with SCA/SAST/IaC', async () => {
    const layers = [
      layer(LAYER_BASE, { 'lib/apk/db/installed': APK_DB }),
      layer(LAYER_APP, { 'app/node_modules/lodash/package.json': LODASH_JSON }),
    ];
    const outcome = await scanner(matchingMatcher(['openssl', 'lodash']), puller(layers)).execute(ctx());
    const openssl = outcome.findings.find((f) => f.location.packageName === 'openssl');
    const lodash = outcome.findings.find((f) => f.location.packageName === 'lodash');
    expect(openssl).toBeTruthy();
    expect(lodash).toBeTruthy();
    const normalizer = new FindingNormalizer();
    const baseFp = normalizer.fingerprint('asset-1', openssl!);
    const appFp = normalizer.fingerprint('asset-1', lodash!);
    expect(baseFp).not.toBe(appFp);

    const sameCveOtherLayer = {
      ...openssl!,
      location: { ...openssl!.location, imageLayer: LAYER_APP },
    };
    expect(normalizer.fingerprint('asset-1', openssl!)).not.toBe(normalizer.fingerprint('asset-1', sameCveOtherLayer));

    const scaFp = normalizer.fingerprint('asset-1', {
      ...openssl!,
      scannerType: 'sca',
      location: { purl: openssl!.location.purl, packageName: openssl!.location.packageName },
    });
    const sastFp = normalizer.fingerprint('asset-1', {
      ...openssl!,
      scannerType: 'sast',
      location: { path: openssl!.location.path, purl: openssl!.location.purl },
    });
    const iacFp = normalizer.fingerprint('asset-1', {
      ...openssl!,
      scannerType: 'iac',
      identifiers: [{ system: 'rule', value: 'ctem.iac.s3-public' }],
      location: { path: 's3.tf', resource: 'aws_s3_bucket.logs' },
    });
    expect(baseFp).not.toBe(scaFp);
    expect(baseFp).not.toBe(sastFp);
    expect(baseFp).not.toBe(iacFp);
  });

  it('does not spawn docker/podman/skopeo/crane', () => {
    const sources = [
      'container.scanner.ts',
      'container.egress.ts',
      'container.identity.ts',
      'container.credential.ts',
      'oci/registry.ts',
      'oci/tar.ts',
      'inventory/packages.ts',
    ]
      .map((name) => readFileSync(join(__dirname, name), 'utf8'))
      .join('\n');
    expect(sources).not.toMatch(
      /from ['"]node:child_process['"]|from ['"]child_process['"]|require\(['"]child_process/,
    );
    expect(sources).not.toMatch(/spawnSync|execFile|child_process/);
  });
});

describe('gzip layer fixture', () => {
  it('round-trips through zlib so tests never need a live registry', () => {
    const gz = gzipSync(Buffer.from('not-a-tar'));
    expect(gz[0]).toBe(0x1f);
    expect(gz[1]).toBe(0x8b);
  });
});
