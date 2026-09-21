import { gzipSync } from 'node:zlib';
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ScanContext } from '@ctem/scanner-sdk';
import { FindingNormalizer } from '../../findings-service/src/findings/finding-normalizer';
import { ContainerScanError, ContainerScanner } from './container.scanner';
import { ContainerCredentialError } from './container.credential';
import { ContainerEgressError } from './container.egress';
import { parseGhcrImageRef, parseContainerImageRef, ContainerIdentityError } from './container.identity';
import { DEMO_CONTAINER_DIGEST, DEMO_CONTAINER_IMAGE } from '@ctem/testing';
import { ContainerInventoryError } from './inventory/packages';
import { ContainerPullError, type ImagePuller, type LayerSnapshot } from './oci/registry';
import type { EcrImagePuller } from './oci/ecr.registry';
import type { GcrImagePuller } from './oci/gcr.registry';
import type { AcrImagePuller } from './oci/acr.registry';
import type { DockerhubImagePuller } from './oci/dockerhub.registry';
import type { QuayImagePuller } from './oci/quay.registry';
import type { VulnMatcher } from '@ctem/vuln-intel';

const DIGEST = `sha256:${'a'.repeat(64)}`;
const LAYER_BASE = `sha256:${'b'.repeat(64)}`;
const LAYER_APP = `sha256:${'c'.repeat(64)}`;
const GHCR_KEY = `ghcr:acme/payments-api@${DIGEST}`;
const ACCOUNT = '123456789012';
const REGION = 'us-east-1';
const ECR_KEY = `ecr:${ACCOUNT}/payments-api@${DIGEST}`;
const PROJECT = 'acme-prod';
const GCR_LOCATION = 'us-central1';
const GCR_KEY = `gcr:${PROJECT}/${GCR_LOCATION}/payments-api/web@${DIGEST}`;
const SUB = '11111111-1111-1111-1111-111111111111';
const AZURE_TENANT = '22222222-2222-2222-2222-222222222222';
const AZURE_CLIENT = '33333333-3333-3333-3333-333333333333';
const RG = 'rg-prod';
const ACR_REGISTRY = 'acmeprod';
const ACR_KEY = `acr:${SUB}/${RG}/${ACR_REGISTRY}/payments-api@${DIGEST}`;
const DOCKERHUB_NS = 'acme';
const DOCKERHUB_REPO = 'payments-api';
const DOCKERHUB_KEY = `dockerhub:${DOCKERHUB_NS}/${DOCKERHUB_REPO}@${DIGEST}`;
const QUAY_NS = 'acme';
const QUAY_REPO = 'payments-api';
const QUAY_KEY = `quay:${QUAY_NS}/${QUAY_REPO}@${DIGEST}`;
const gcpPem = generateKeyPairSync('rsa', { modulusLength: 2048 })
  .privateKey.export({ type: 'pkcs8', format: 'pem' })
  .toString();

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

function unusedEcr(): EcrImagePuller {
  return {
    pull: vi.fn(async () => {
      throw new Error('ECR puller must not be called for GHCR identities');
    }),
  };
}

function unusedGhcr(): ImagePuller {
  return {
    pull: vi.fn(async () => {
      throw new Error('GHCR puller must not be called for ECR/GCR identities');
    }),
  };
}

function unusedGcr(): GcrImagePuller {
  return {
    pull: vi.fn(async () => {
      throw new Error('GCR puller must not be called for GHCR/ECR/ACR identities');
    }),
  };
}

function unusedAcr(): AcrImagePuller {
  return {
    pull: vi.fn(async () => {
      throw new Error('ACR puller must not be called for GHCR/ECR/GCR identities');
    }),
  };
}

function unusedDockerhub(): DockerhubImagePuller {
  return {
    pull: vi.fn(async () => {
      throw new Error('Docker Hub puller must not be called for GHCR/ECR/GCR/ACR/Quay identities');
    }),
  };
}

function unusedQuay(): QuayImagePuller {
  return {
    pull: vi.fn(async () => {
      throw new Error('Quay puller must not be called for GHCR/ECR/GCR/ACR/Docker Hub identities');
    }),
  };
}

function ecrPuller(layers: LayerSnapshot[], spy?: (ref: unknown) => void): EcrImagePuller {
  return {
    pull: vi.fn(async (ref, _creds, checkDeadline) => {
      spy?.(ref);
      if (!checkDeadline()) throw new ContainerPullError('Job deadline exceeded mid-pull');
      return { digest: DIGEST, owner: ACCOUNT, name: 'payments-api', layers };
    }),
  };
}

function gcrPuller(layers: LayerSnapshot[], spy?: (ref: unknown) => void): GcrImagePuller {
  return {
    pull: vi.fn(async (ref, _creds, checkDeadline) => {
      spy?.(ref);
      if (!checkDeadline()) throw new ContainerPullError('Job deadline exceeded mid-pull');
      return { digest: DIGEST, owner: PROJECT, name: 'payments-api/web', layers };
    }),
  };
}

function acrPuller(layers: LayerSnapshot[], spy?: (ref: unknown) => void): AcrImagePuller {
  return {
    pull: vi.fn(async (ref, _creds, checkDeadline) => {
      spy?.(ref);
      if (!checkDeadline()) throw new ContainerPullError('Job deadline exceeded mid-pull');
      return { digest: DIGEST, owner: ACR_REGISTRY, name: 'payments-api', layers };
    }),
  };
}

function dockerhubPuller(layers: LayerSnapshot[], spy?: (ref: unknown) => void): DockerhubImagePuller {
  return {
    pull: vi.fn(async (ref, _creds, checkDeadline) => {
      spy?.(ref);
      if (!checkDeadline()) throw new ContainerPullError('Job deadline exceeded mid-pull');
      return { digest: DIGEST, owner: DOCKERHUB_NS, name: DOCKERHUB_REPO, layers };
    }),
  };
}

function quayPuller(layers: LayerSnapshot[], spy?: (ref: unknown) => void): QuayImagePuller {
  return {
    pull: vi.fn(async (ref, _token, checkDeadline) => {
      spy?.(ref);
      if (!checkDeadline()) throw new ContainerPullError('Job deadline exceeded mid-pull');
      return { digest: DIGEST, owner: QUAY_NS, name: QUAY_REPO, layers };
    }),
  };
}

function scanner(
  matcher = matchingMatcher(),
  registry?: ImagePuller,
  ecr?: EcrImagePuller,
  gcr?: GcrImagePuller,
  acr?: AcrImagePuller,
  dockerhub?: DockerhubImagePuller,
  quay?: QuayImagePuller,
): ContainerScanner {
  return new ContainerScanner(
    matcher as unknown as VulnMatcher,
    (registry ?? puller([layer(LAYER_BASE, { 'lib/apk/db/installed': APK_DB })])) as never,
    (ecr ?? unusedEcr()) as never,
    (gcr ?? unusedGcr()) as never,
    (acr ?? unusedAcr()) as never,
    (dockerhub ?? unusedDockerhub()) as never,
    (quay ?? unusedQuay()) as never,
  );
}

function ecrTarget(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    kind: 'container_image',
    externalKey: ECR_KEY,
    accountId: ACCOUNT,
    region: REGION,
    repository: 'payments-api',
    digest: DIGEST,
    ...overrides,
  };
}

function gcrTarget(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    kind: 'container_image',
    externalKey: GCR_KEY,
    projectId: PROJECT,
    location: GCR_LOCATION,
    repository: 'payments-api',
    image: 'web',
    digest: DIGEST,
    ...overrides,
  };
}

function acrTarget(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    kind: 'container_image',
    externalKey: ACR_KEY,
    subscriptionId: SUB,
    resourceGroup: RG,
    registry: ACR_REGISTRY,
    loginServer: `${ACR_REGISTRY}.azurecr.io`,
    repository: 'payments-api',
    digest: DIGEST,
    ...overrides,
  };
}

function dockerhubTarget(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    kind: 'container_image',
    externalKey: DOCKERHUB_KEY,
    namespace: DOCKERHUB_NS,
    repository: DOCKERHUB_REPO,
    digest: DIGEST,
    ...overrides,
  };
}

function quayTarget(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    kind: 'container_image',
    externalKey: QUAY_KEY,
    source: 'quay',
    namespace: QUAY_NS,
    repository: QUAY_REPO,
    digest: DIGEST,
    ...overrides,
  };
}

afterEach(() => {
  delete process.env.GITHUB_TOKEN;
  delete process.env.AWS_ACCESS_KEY_ID;
  delete process.env.AWS_SECRET_ACCESS_KEY;
  delete process.env.AWS_SESSION_TOKEN;
  delete process.env.GCP_CLIENT_EMAIL;
  delete process.env.GCP_PRIVATE_KEY;
  delete process.env.AZURE_TENANT_ID;
  delete process.env.AZURE_CLIENT_ID;
  delete process.env.AZURE_CLIENT_SECRET;
  delete process.env.DOCKERHUB_USERNAME;
  delete process.env.DOCKERHUB_TOKEN;
  delete process.env.QUAY_TOKEN;
});

describe('ContainerScanner.supports', () => {
  it('supports container_image only — not kubernetes_workload, repository, or iac_stack', () => {
    const s = scanner();
    expect(s.supports({ target: { kind: 'container_image' } } as never)).toBe(true);
    expect(s.supports({ target: { kind: 'kubernetes_workload' } } as never)).toBe(false);
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
    await expect(
      s.execute(
        ctx({
          options: { pkgDevHost: 'us-central1-docker.pkg.dev' },
        }),
      ),
    ).rejects.toThrow(ContainerEgressError);
    await expect(
      s.execute(
        ctx({
          target: {
            kind: 'container_image',
            externalKey: GCR_KEY,
            registryUrl: 'https://us-central1-docker.pkg.dev',
          },
        }),
      ),
    ).rejects.toThrow(ContainerEgressError);
    await expect(
      s.execute(
        ctx({
          target: {
            kind: 'container_image',
            externalKey: ACR_KEY,
            azurecrUrl: 'https://acmeprod.azurecr.io',
          },
        }),
      ),
    ).rejects.toThrow(ContainerEgressError);
    await expect(
      s.execute(
        ctx({
          options: { loginServer: 'https://acmeprod.azurecr.io' },
          target: acrTarget(),
        }),
      ),
    ).rejects.toThrow(/loginServer|tenant-writable/);
    await expect(
      s.execute(
        ctx({
          target: {
            kind: 'container_image',
            externalKey: DOCKERHUB_KEY,
            registryUrl: 'https://registry-1.docker.io',
          },
        }),
      ),
    ).rejects.toThrow(ContainerEgressError);
    await expect(
      s.execute(
        ctx({
          options: { index: 'docker.io' },
          target: dockerhubTarget(),
        }),
      ),
    ).rejects.toThrow(/tenant-writable/);
    await expect(
      s.execute(
        ctx({
          target: {
            kind: 'container_image',
            externalKey: QUAY_KEY,
            quayUrl: 'https://quay.io',
          },
        }),
      ),
    ).rejects.toThrow(ContainerEgressError);
    await expect(
      s.execute(
        ctx({
          options: { host: 'quay.acme.example' },
          target: quayTarget(),
        }),
      ),
    ).rejects.toThrow(/tenant-writable/);
    await expect(
      s.execute(
        ctx({
          options: { baseUrl: 'https://registry.internal' },
          target: quayTarget(),
        }),
      ),
    ).rejects.toThrow(/tenant-writable/);
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
            externalKey: `gcr.io/proj/app@${DIGEST}`,
          },
        }),
      ),
    ).rejects.toThrow(/non-digest|malformed/);
    await expect(
      s.execute(
        ctx({
          target: {
            kind: 'container_image',
            externalKey: `acr:acct/app@${DIGEST}`,
          },
        }),
      ),
    ).rejects.toThrow(/non-digest|malformed/);
    await expect(
      s.execute(
        ctx({
          target: {
            kind: 'container_image',
            externalKey: `quay:acme/app:latest`,
          },
        }),
      ),
    ).rejects.toThrow(/non-digest|malformed/);
    await expect(
      s.execute(
        ctx({
          target: {
            kind: 'container_image',
            externalKey: `quay.io/acme/app@${DIGEST}`,
          },
        }),
      ),
    ).rejects.toThrow(/non-digest|malformed/);
    await expect(
      s.execute(
        ctx({
          target: {
            kind: 'container_image',
            externalKey: `dockerhub:acme/app:latest`,
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

  it('accepts the demo seed digest GHCR identity', () => {
    expect(
      parseGhcrImageRef({
        kind: DEMO_CONTAINER_IMAGE.kind,
        externalKey: DEMO_CONTAINER_IMAGE.externalKey,
        ...DEMO_CONTAINER_IMAGE.attributes,
      }),
    ).toEqual({
      owner: 'demo',
      name: 'payments-api',
      digest: DEMO_CONTAINER_DIGEST,
    });
    expect(
      parseContainerImageRef({
        kind: DEMO_CONTAINER_IMAGE.kind,
        externalKey: DEMO_CONTAINER_IMAGE.externalKey,
        ...DEMO_CONTAINER_IMAGE.attributes,
      }),
    ).toEqual({
      kind: 'ghcr',
      owner: 'demo',
      name: 'payments-api',
      digest: DEMO_CONTAINER_DIGEST,
    });
  });

  it('accepts an ECR digest identity and refuses a tag or missing region', () => {
    expect(parseContainerImageRef(ecrTarget())).toEqual({
      kind: 'ecr',
      accountId: ACCOUNT,
      repositoryName: 'payments-api',
      digest: DIGEST,
      region: REGION,
    });
    expect(() =>
      parseContainerImageRef({
        kind: 'container_image',
        externalKey: `ecr:${ACCOUNT}/payments-api:latest`,
        region: REGION,
      }),
    ).toThrow(ContainerIdentityError);
    expect(() =>
      parseContainerImageRef({
        kind: 'container_image',
        externalKey: ECR_KEY,
      }),
    ).toThrow(/region/);
  });

  it('accepts a GCR digest identity and refuses a tag or tenant pkg.dev host', () => {
    expect(parseContainerImageRef(gcrTarget())).toEqual({
      kind: 'gcr',
      projectId: PROJECT,
      location: GCR_LOCATION,
      repository: 'payments-api',
      image: 'web',
      digest: DIGEST,
    });
    expect(parseContainerImageRef(gcrTarget({ image: 'web/api', externalKey: `gcr:${PROJECT}/${GCR_LOCATION}/payments-api/web/api@${DIGEST}` }))).toMatchObject({
      kind: 'gcr',
      image: 'web/api',
    });
    expect(() =>
      parseContainerImageRef({
        kind: 'container_image',
        externalKey: `gcr:${PROJECT}/${GCR_LOCATION}/payments-api/web:latest`,
      }),
    ).toThrow(ContainerIdentityError);
    expect(() =>
      parseContainerImageRef({
        kind: 'container_image',
        externalKey: GCR_KEY,
        pkgDevHost: 'us-central1-docker.pkg.dev',
      }),
    ).toThrow(ContainerEgressError);
    expect(() =>
      parseContainerImageRef({
        kind: 'container_image',
        externalKey: GCR_KEY,
        location: 'us-central1-docker.pkg.dev',
      }),
    ).toThrow(/location is an id|does not match/);
    expect(() =>
      parseContainerImageRef({
        kind: 'container_image',
        externalKey: `acr:11111111-1111-1111-1111-111111111111/rg/reg/app@${DIGEST}`,
      }),
    ).toThrow(/non-digest|malformed/);
  });

  it('accepts an ACR digest identity and refuses a tag, tenant loginServer URL, or host override', () => {
    expect(parseContainerImageRef(acrTarget())).toEqual({
      kind: 'acr',
      subscriptionId: SUB,
      resourceGroup: RG,
      registry: ACR_REGISTRY,
      repository: 'payments-api',
      digest: DIGEST,
    });
    expect(
      parseContainerImageRef(
        acrTarget({
          repository: 'team/api',
          externalKey: `acr:${SUB}/${RG}/${ACR_REGISTRY}/team/api@${DIGEST}`,
        }),
      ),
    ).toMatchObject({
      kind: 'acr',
      repository: 'team/api',
    });
    expect(() =>
      parseContainerImageRef({
        kind: 'container_image',
        externalKey: `acr:${SUB}/${RG}/${ACR_REGISTRY}/payments-api:latest`,
      }),
    ).toThrow(ContainerIdentityError);
    expect(() =>
      parseContainerImageRef({
        kind: 'container_image',
        externalKey: ACR_KEY,
        azurecrUrl: 'https://acmeprod.azurecr.io',
      }),
    ).toThrow(ContainerEgressError);
    expect(() =>
      parseContainerImageRef({
        kind: 'container_image',
        externalKey: ACR_KEY,
        loginServer: 'https://acmeprod.azurecr.io',
      }),
    ).toThrow(/loginServer|tenant-writable/);
    expect(() =>
      parseContainerImageRef({
        kind: 'container_image',
        externalKey: ACR_KEY,
        loginServer: 'evilreg.azurecr.io',
      }),
    ).toThrow(/loginServer|identity-derived/);
    expect(() =>
      parseContainerImageRef({
        kind: 'container_image',
        externalKey: ACR_KEY,
        registry: 'acmeprod.azurecr.io',
      }),
    ).toThrow(/registry is an id|does not match|tenant-writable/);
  });

  it('accepts a Docker Hub digest identity and refuses a tag, tenant URL, or host override', () => {
    expect(parseContainerImageRef(dockerhubTarget())).toEqual({
      kind: 'dockerhub',
      namespace: DOCKERHUB_NS,
      repository: DOCKERHUB_REPO,
      digest: DIGEST,
    });
    expect(
      parseContainerImageRef({
        kind: 'container_image',
        namespace: DOCKERHUB_NS,
        repository: DOCKERHUB_REPO,
        digest: DIGEST,
      }),
    ).toEqual({
      kind: 'dockerhub',
      namespace: DOCKERHUB_NS,
      repository: DOCKERHUB_REPO,
      digest: DIGEST,
    });
    expect(() =>
      parseContainerImageRef({
        kind: 'container_image',
        externalKey: `dockerhub:${DOCKERHUB_NS}/${DOCKERHUB_REPO}:latest`,
      }),
    ).toThrow(ContainerIdentityError);
    expect(() =>
      parseContainerImageRef({
        kind: 'container_image',
        externalKey: `dockerhub:${DOCKERHUB_NS}/${DOCKERHUB_REPO}@sha256:deadbeef`,
      }),
    ).toThrow(ContainerIdentityError);
    expect(() =>
      parseContainerImageRef({
        kind: 'container_image',
        externalKey: DOCKERHUB_KEY,
        registryUrl: 'https://registry-1.docker.io',
      }),
    ).toThrow(ContainerEgressError);
    expect(() =>
      parseContainerImageRef({
        kind: 'container_image',
        externalKey: DOCKERHUB_KEY,
        index: 'docker.io',
      }),
    ).toThrow(/tenant-writable/);
    expect(() =>
      parseContainerImageRef({
        kind: 'container_image',
        externalKey: `dockerhub:registry-1.docker.io/${DOCKERHUB_REPO}@${DIGEST}`,
      }),
    ).toThrow(/namespace|tenant-writable|not a valid/);
  });

  it('accepts a Quay digest identity and refuses a tag, tenant URL, or self-hosted host', () => {
    expect(parseContainerImageRef(quayTarget())).toEqual({
      kind: 'quay',
      namespace: QUAY_NS,
      repository: QUAY_REPO,
      digest: DIGEST,
    });
    expect(
      parseContainerImageRef({
        kind: 'container_image',
        source: 'quay',
        namespace: QUAY_NS,
        repository: QUAY_REPO,
        digest: DIGEST,
      }),
    ).toEqual({
      kind: 'quay',
      namespace: QUAY_NS,
      repository: QUAY_REPO,
      digest: DIGEST,
    });
    expect(
      parseContainerImageRef(
        quayTarget({
          repository: 'team/api',
          externalKey: `quay:${QUAY_NS}/team/api@${DIGEST}`,
        }),
      ),
    ).toMatchObject({
      kind: 'quay',
      repository: 'team/api',
    });
    expect(() =>
      parseContainerImageRef({
        kind: 'container_image',
        externalKey: `quay:${QUAY_NS}/${QUAY_REPO}:latest`,
      }),
    ).toThrow(ContainerIdentityError);
    expect(() =>
      parseContainerImageRef({
        kind: 'container_image',
        externalKey: `quay:${QUAY_NS}/${QUAY_REPO}@sha256:deadbeef`,
      }),
    ).toThrow(ContainerIdentityError);
    expect(() =>
      parseContainerImageRef({
        kind: 'container_image',
        externalKey: QUAY_KEY,
        quayUrl: 'https://quay.io',
      }),
    ).toThrow(ContainerEgressError);
    expect(() =>
      parseContainerImageRef({
        kind: 'container_image',
        externalKey: QUAY_KEY,
        host: 'quay.acme.example',
      }),
    ).toThrow(/tenant-writable/);
    expect(() =>
      parseContainerImageRef({
        kind: 'container_image',
        externalKey: QUAY_KEY,
        baseUrl: 'https://registry.internal',
      }),
    ).toThrow(/tenant-writable/);
    expect(() =>
      parseContainerImageRef({
        kind: 'container_image',
        externalKey: QUAY_KEY,
        authority: 'quay.enterprise.example',
      }),
    ).toThrow(/tenant-writable/);
    expect(() =>
      parseContainerImageRef({
        kind: 'container_image',
        externalKey: `quay:quay.io/${QUAY_REPO}@${DIGEST}`,
      }),
    ).toThrow(/namespace|tenant-writable|not a valid/);
    expect(
      parseContainerImageRef({
        kind: 'container_image',
        namespace: DOCKERHUB_NS,
        repository: DOCKERHUB_REPO,
        digest: DIGEST,
      }),
    ).toEqual({
      kind: 'dockerhub',
      namespace: DOCKERHUB_NS,
      repository: DOCKERHUB_REPO,
      digest: DIGEST,
    });
  });

  it('scans an ECR-discovered digest through the same inventory + vuln match', async () => {
    process.env.AWS_ACCESS_KEY_ID = 'AKIATEST';
    process.env.AWS_SECRET_ACCESS_KEY = 'secret';
    const layers = [
      layer(LAYER_BASE, { 'lib/apk/db/installed': APK_DB }),
      layer(LAYER_APP, { 'app/node_modules/lodash/package.json': LODASH_JSON }),
    ];
    const ecr = ecrPuller(layers);
    const matcher = matchingMatcher(['openssl', 'lodash']);
    const outcome = await scanner(matcher, unusedEcr() as never, ecr).execute(
      ctx({
        target: ecrTarget(),
        credentialRef: 'env:AWS_ACCESS_KEY_ID',
      }),
    );
    expect(ecr.pull).toHaveBeenCalledOnce();
    expect(outcome.findings.length).toBeGreaterThanOrEqual(2);
    expect((outcome.rawOutput as { image: string }).image).toBe(
      `${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com/payments-api@${DIGEST}`,
    );
    expect((outcome.rawOutput as { complete: boolean; truncated: boolean }).complete).toBe(true);
    expect((outcome.rawOutput as { truncated: boolean }).truncated).toBe(false);
  });

  it('fails an ECR pull when AWS_* credentials are missing or not env:AWS_*', async () => {
    const ecr = ecrPuller([]);
    const s = scanner(matchingMatcher(), unusedEcr() as never, ecr);
    await expect(
      s.execute(ctx({ target: ecrTarget(), credentialRef: null })),
    ).rejects.toThrow(ContainerCredentialError);
    await expect(
      s.execute(ctx({ target: ecrTarget(), credentialRef: 'env:AWS_ACCESS_KEY_ID' })),
    ).rejects.toThrow(/cannot be used/);
    process.env.GITHUB_TOKEN = 'ghp_test';
    await expect(
      s.execute(ctx({ target: ecrTarget(), credentialRef: 'env:GITHUB_TOKEN' })),
    ).rejects.toThrow(/env:AWS_\*/);
    expect(ecr.pull).not.toHaveBeenCalled();
  });

  it('scans a GCR-discovered digest through the same inventory + vuln match', async () => {
    process.env.GCP_CLIENT_EMAIL = 'ctem@acme-prod.iam.gserviceaccount.com';
    process.env.GCP_PRIVATE_KEY = gcpPem;
    const layers = [
      layer(LAYER_BASE, { 'lib/apk/db/installed': APK_DB }),
      layer(LAYER_APP, { 'app/node_modules/lodash/package.json': LODASH_JSON }),
    ];
    const gcr = gcrPuller(layers);
    const matcher = matchingMatcher(['openssl', 'lodash']);
    const outcome = await scanner(matcher, unusedGhcr(), unusedEcr(), gcr).execute(
      ctx({
        target: gcrTarget(),
        credentialRef: 'env:GCP_CLIENT_EMAIL',
      }),
    );
    expect(gcr.pull).toHaveBeenCalledOnce();
    expect(outcome.findings.length).toBeGreaterThanOrEqual(2);
    expect((outcome.rawOutput as { image: string }).image).toBe(
      `${GCR_LOCATION}-docker.pkg.dev/${PROJECT}/payments-api/web@${DIGEST}`,
    );
    expect((outcome.rawOutput as { complete: boolean; truncated: boolean }).complete).toBe(true);
    expect((outcome.rawOutput as { truncated: boolean }).truncated).toBe(false);
  });

  it('fails a GCR pull when GCP_* credentials are missing or not env:GCP_*', async () => {
    const gcr = gcrPuller([]);
    const s = scanner(matchingMatcher(), unusedGhcr(), unusedEcr(), gcr);
    await expect(
      s.execute(ctx({ target: gcrTarget(), credentialRef: null })),
    ).rejects.toThrow(ContainerCredentialError);
    await expect(
      s.execute(ctx({ target: gcrTarget(), credentialRef: 'env:GCP_CLIENT_EMAIL' })),
    ).rejects.toThrow(/cannot be used/);
    process.env.GITHUB_TOKEN = 'ghp_test';
    await expect(
      s.execute(ctx({ target: gcrTarget(), credentialRef: 'env:GITHUB_TOKEN' })),
    ).rejects.toThrow(/env:GCP_\*/);
    expect(gcr.pull).not.toHaveBeenCalled();
  });

  it('scans an ACR-discovered digest through the same inventory + vuln match', async () => {
    process.env.AZURE_TENANT_ID = AZURE_TENANT;
    process.env.AZURE_CLIENT_ID = AZURE_CLIENT;
    process.env.AZURE_CLIENT_SECRET = 'super-secret';
    const layers = [
      layer(LAYER_BASE, { 'lib/apk/db/installed': APK_DB }),
      layer(LAYER_APP, { 'app/node_modules/lodash/package.json': LODASH_JSON }),
    ];
    const acr = acrPuller(layers);
    const matcher = matchingMatcher(['openssl', 'lodash']);
    const outcome = await scanner(matcher, unusedGhcr(), unusedEcr(), unusedGcr(), acr).execute(
      ctx({
        target: acrTarget(),
        credentialRef: 'env:AZURE_CLIENT_ID',
      }),
    );
    expect(acr.pull).toHaveBeenCalledOnce();
    expect(outcome.findings.length).toBeGreaterThanOrEqual(2);
    expect((outcome.rawOutput as { image: string }).image).toBe(
      `${ACR_REGISTRY}.azurecr.io/payments-api@${DIGEST}`,
    );
    expect((outcome.rawOutput as { complete: boolean; truncated: boolean }).complete).toBe(true);
    expect((outcome.rawOutput as { truncated: boolean }).truncated).toBe(false);
  });

  it('fails an ACR pull when AZURE_* credentials are missing or not env:AZURE_*', async () => {
    const acr = acrPuller([]);
    const s = scanner(matchingMatcher(), unusedGhcr(), unusedEcr(), unusedGcr(), acr);
    await expect(
      s.execute(ctx({ target: acrTarget(), credentialRef: null })),
    ).rejects.toThrow(ContainerCredentialError);
    await expect(
      s.execute(ctx({ target: acrTarget(), credentialRef: 'env:AZURE_CLIENT_ID' })),
    ).rejects.toThrow(/cannot be used/);
    process.env.GITHUB_TOKEN = 'ghp_test';
    await expect(
      s.execute(ctx({ target: acrTarget(), credentialRef: 'env:GITHUB_TOKEN' })),
    ).rejects.toThrow(/env:AZURE_\*/);
    expect(acr.pull).not.toHaveBeenCalled();
  });

  it('scans a Docker Hub-discovered digest through the same inventory + vuln match', async () => {
    process.env.DOCKERHUB_USERNAME = 'acme';
    process.env.DOCKERHUB_TOKEN = 'dckr_pat_test';
    const layers = [
      layer(LAYER_BASE, { 'lib/apk/db/installed': APK_DB }),
      layer(LAYER_APP, { 'app/node_modules/lodash/package.json': LODASH_JSON }),
    ];
    const dockerhub = dockerhubPuller(layers);
    const matcher = matchingMatcher(['openssl', 'lodash']);
    const outcome = await scanner(
      matcher,
      unusedGhcr(),
      unusedEcr(),
      unusedGcr(),
      unusedAcr(),
      dockerhub,
    ).execute(
      ctx({
        target: dockerhubTarget(),
        credentialRef: 'env:DOCKERHUB_TOKEN',
      }),
    );
    expect(dockerhub.pull).toHaveBeenCalledOnce();
    expect(outcome.findings.length).toBeGreaterThanOrEqual(2);
    expect((outcome.rawOutput as { image: string }).image).toBe(
      `registry-1.docker.io/${DOCKERHUB_NS}/${DOCKERHUB_REPO}@${DIGEST}`,
    );
    expect((outcome.rawOutput as { complete: boolean; truncated: boolean }).complete).toBe(true);
    expect((outcome.rawOutput as { truncated: boolean }).truncated).toBe(false);
  });

  it('fails a Docker Hub pull when DOCKERHUB_* credentials are missing or not env:DOCKERHUB_*', async () => {
    const dockerhub = dockerhubPuller([]);
    const s = scanner(matchingMatcher(), unusedGhcr(), unusedEcr(), unusedGcr(), unusedAcr(), dockerhub);
    await expect(
      s.execute(ctx({ target: dockerhubTarget(), credentialRef: null })),
    ).rejects.toThrow(ContainerCredentialError);
    await expect(
      s.execute(ctx({ target: dockerhubTarget(), credentialRef: 'env:DOCKERHUB_TOKEN' })),
    ).rejects.toThrow(/cannot be used/);
    process.env.GITHUB_TOKEN = 'ghp_test';
    await expect(
      s.execute(ctx({ target: dockerhubTarget(), credentialRef: 'env:GITHUB_TOKEN' })),
    ).rejects.toThrow(/env:DOCKERHUB_\*/);
    expect(dockerhub.pull).not.toHaveBeenCalled();
  });

  it('scans a Quay-discovered digest through the same inventory + vuln match', async () => {
    process.env.QUAY_TOKEN = 'quay_test';
    const layers = [
      layer(LAYER_BASE, { 'lib/apk/db/installed': APK_DB }),
      layer(LAYER_APP, { 'app/node_modules/lodash/package.json': LODASH_JSON }),
    ];
    const quay = quayPuller(layers);
    const matcher = matchingMatcher(['openssl', 'lodash']);
    const outcome = await scanner(
      matcher,
      unusedGhcr(),
      unusedEcr(),
      unusedGcr(),
      unusedAcr(),
      unusedDockerhub(),
      quay,
    ).execute(
      ctx({
        target: quayTarget(),
        credentialRef: 'env:QUAY_TOKEN',
      }),
    );
    expect(quay.pull).toHaveBeenCalledOnce();
    expect(outcome.findings.length).toBeGreaterThanOrEqual(2);
    expect((outcome.rawOutput as { image: string }).image).toBe(
      `quay.io/${QUAY_NS}/${QUAY_REPO}@${DIGEST}`,
    );
    expect((outcome.rawOutput as { complete: boolean; truncated: boolean }).complete).toBe(true);
    expect((outcome.rawOutput as { truncated: boolean }).truncated).toBe(false);
  });

  it('fails a Quay pull when QUAY_* credentials are missing or not env:QUAY_*', async () => {
    const quay = quayPuller([]);
    const s = scanner(
      matchingMatcher(),
      unusedGhcr(),
      unusedEcr(),
      unusedGcr(),
      unusedAcr(),
      unusedDockerhub(),
      quay,
    );
    await expect(
      s.execute(ctx({ target: quayTarget(), credentialRef: null })),
    ).rejects.toThrow(ContainerCredentialError);
    await expect(
      s.execute(ctx({ target: quayTarget(), credentialRef: 'env:QUAY_TOKEN' })),
    ).rejects.toThrow(/cannot be used/);
    process.env.GITHUB_TOKEN = 'ghp_test';
    await expect(
      s.execute(ctx({ target: quayTarget(), credentialRef: 'env:GITHUB_TOKEN' })),
    ).rejects.toThrow(/env:QUAY_\*/);
    process.env.DOCKERHUB_USERNAME = 'acme';
    process.env.DOCKERHUB_TOKEN = 'dckr_pat_test';
    await expect(
      s.execute(ctx({ target: quayTarget(), credentialRef: 'env:DOCKERHUB_TOKEN' })),
    ).rejects.toThrow(/env:QUAY_\*/);
    expect(quay.pull).not.toHaveBeenCalled();
  });

  it('fails a Quay pull that is incomplete or hits the deadline mid-pull', async () => {
    process.env.QUAY_TOKEN = 'quay_test';
    const failPull: QuayImagePuller = {
      pull: vi.fn(async () => {
        throw new ContainerPullError('Quay blob GET returned 502 — refusing pull');
      }),
    };
    await expect(
      scanner(
        matchingMatcher(),
        unusedGhcr(),
        unusedEcr(),
        unusedGcr(),
        unusedAcr(),
        unusedDockerhub(),
        failPull,
      ).execute(ctx({ target: quayTarget(), credentialRef: 'env:QUAY_TOKEN' })),
    ).rejects.toThrow(ContainerPullError);

    const midPull: QuayImagePuller = {
      pull: vi.fn(async (_ref, _token, checkDeadline) => {
        if (!checkDeadline()) throw new ContainerPullError('Job deadline exceeded mid-pull');
        return { digest: DIGEST, owner: QUAY_NS, name: QUAY_REPO, layers: [] };
      }),
    };
    let allow = true;
    await expect(
      scanner(
        matchingMatcher(),
        unusedGhcr(),
        unusedEcr(),
        unusedGcr(),
        unusedAcr(),
        unusedDockerhub(),
        midPull,
      ).execute({
        ...ctx({ target: quayTarget(), credentialRef: 'env:QUAY_TOKEN' }),
        checkDeadline: () => {
          const ok = allow;
          allow = false;
          return ok;
        },
      }),
    ).rejects.toThrow(/deadline/);
  });

  it('fails a Docker Hub pull that is incomplete or hits the deadline mid-pull', async () => {
    process.env.DOCKERHUB_USERNAME = 'acme';
    process.env.DOCKERHUB_TOKEN = 'dckr_pat_test';
    const failPull: DockerhubImagePuller = {
      pull: vi.fn(async () => {
        throw new ContainerPullError('Docker Hub blob GET returned 502 — refusing pull');
      }),
    };
    await expect(
      scanner(matchingMatcher(), unusedGhcr(), unusedEcr(), unusedGcr(), unusedAcr(), failPull).execute(
        ctx({ target: dockerhubTarget(), credentialRef: 'env:DOCKERHUB_TOKEN' }),
      ),
    ).rejects.toThrow(ContainerPullError);

    const midPull: DockerhubImagePuller = {
      pull: vi.fn(async (_ref, _creds, checkDeadline) => {
        if (!checkDeadline()) throw new ContainerPullError('Job deadline exceeded mid-pull');
        return { digest: DIGEST, owner: DOCKERHUB_NS, name: DOCKERHUB_REPO, layers: [] };
      }),
    };
    let allow = true;
    await expect(
      scanner(matchingMatcher(), unusedGhcr(), unusedEcr(), unusedGcr(), unusedAcr(), midPull).execute({
        ...ctx({ target: dockerhubTarget(), credentialRef: 'env:DOCKERHUB_TOKEN' }),
        checkDeadline: () => {
          const ok = allow;
          allow = false;
          return ok;
        },
      }),
    ).rejects.toThrow(/deadline/);
  });

  it('fails an ACR pull that is incomplete or hits the deadline mid-pull', async () => {
    process.env.AZURE_TENANT_ID = AZURE_TENANT;
    process.env.AZURE_CLIENT_ID = AZURE_CLIENT;
    process.env.AZURE_CLIENT_SECRET = 'super-secret';
    const failPull: AcrImagePuller = {
      pull: vi.fn(async () => {
        throw new ContainerPullError('ACR blob GET returned 502 — refusing pull');
      }),
    };
    await expect(
      scanner(matchingMatcher(), unusedGhcr(), unusedEcr(), unusedGcr(), failPull).execute(
        ctx({ target: acrTarget(), credentialRef: 'env:AZURE_CLIENT_ID' }),
      ),
    ).rejects.toThrow(ContainerPullError);

    const midPull: AcrImagePuller = {
      pull: vi.fn(async (_ref, _creds, checkDeadline) => {
        if (!checkDeadline()) throw new ContainerPullError('Job deadline exceeded mid-pull');
        return { digest: DIGEST, owner: ACR_REGISTRY, name: 'payments-api', layers: [] };
      }),
    };
    let allow = true;
    await expect(
      scanner(matchingMatcher(), unusedGhcr(), unusedEcr(), unusedGcr(), midPull).execute({
        ...ctx({ target: acrTarget(), credentialRef: 'env:AZURE_CLIENT_ID' }),
        checkDeadline: () => {
          const ok = allow;
          allow = false;
          return ok;
        },
      }),
    ).rejects.toThrow(/deadline/);
  });

  it('fails a GCR pull that is incomplete or hits the deadline mid-pull', async () => {
    process.env.GCP_CLIENT_EMAIL = 'ctem@acme-prod.iam.gserviceaccount.com';
    process.env.GCP_PRIVATE_KEY = gcpPem;
    const failPull: GcrImagePuller = {
      pull: vi.fn(async () => {
        throw new ContainerPullError('GCR blob GET returned 502 — refusing pull');
      }),
    };
    await expect(
      scanner(matchingMatcher(), unusedGhcr(), unusedEcr(), failPull).execute(
        ctx({ target: gcrTarget(), credentialRef: 'env:GCP_CLIENT_EMAIL' }),
      ),
    ).rejects.toThrow(ContainerPullError);

    const midPull: GcrImagePuller = {
      pull: vi.fn(async (_ref, _creds, checkDeadline) => {
        if (!checkDeadline()) throw new ContainerPullError('Job deadline exceeded mid-pull');
        return { digest: DIGEST, owner: PROJECT, name: 'payments-api/web', layers: [] };
      }),
    };
    let allow = true;
    await expect(
      scanner(matchingMatcher(), unusedGhcr(), unusedEcr(), midPull).execute({
        ...ctx({ target: gcrTarget(), credentialRef: 'env:GCP_CLIENT_EMAIL' }),
        checkDeadline: () => {
          const ok = allow;
          allow = false;
          return ok;
        },
      }),
    ).rejects.toThrow(/deadline/);
  });

  it('fails an ECR pull that is incomplete or hits the deadline mid-pull', async () => {
    process.env.AWS_ACCESS_KEY_ID = 'AKIATEST';
    process.env.AWS_SECRET_ACCESS_KEY = 'secret';
    const failPull: EcrImagePuller = {
      pull: vi.fn(async () => {
        throw new ContainerPullError('ECR blob GET returned 502 — refusing pull');
      }),
    };
    await expect(
      scanner(matchingMatcher(), unusedEcr() as never, failPull).execute(
        ctx({ target: ecrTarget(), credentialRef: 'env:AWS_ACCESS_KEY_ID' }),
      ),
    ).rejects.toThrow(ContainerPullError);

    const midPull: EcrImagePuller = {
      pull: vi.fn(async (_ref, _creds, checkDeadline) => {
        if (!checkDeadline()) throw new ContainerPullError('Job deadline exceeded mid-pull');
        return { digest: DIGEST, owner: ACCOUNT, name: 'payments-api', layers: [] };
      }),
    };
    let allow = true;
    await expect(
      scanner(matchingMatcher(), unusedEcr() as never, midPull).execute({
        ...ctx({ target: ecrTarget(), credentialRef: 'env:AWS_ACCESS_KEY_ID' }),
        checkDeadline: () => {
          const ok = allow;
          allow = false;
          return ok;
        },
      }),
    ).rejects.toThrow(/deadline/);
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
      'aws.egress.ts',
      'aws.sigv4.ts',
      'gcp.egress.ts',
      'gcp.jwt.ts',
      'azure.egress.ts',
      'azure.token.ts',
      'oci/registry.ts',
      'oci/ecr.registry.ts',
      'oci/gcr.registry.ts',
      'oci/acr.registry.ts',
      'oci/dockerhub.registry.ts',
      'dockerhub.egress.ts',
      'oci/quay.registry.ts',
      'quay.egress.ts',
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
