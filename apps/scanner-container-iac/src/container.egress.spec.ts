import { describe, expect, it } from 'vitest';
import {
  GHCR_REGISTRY_HOST,
  allowlistedAcrBlobRedirect,
  allowlistedAcrOauthUrl,
  allowlistedAcrRegistryUrl,
  allowlistedDockerhubAuthUrl,
  allowlistedDockerhubBlobRedirect,
  allowlistedDockerhubRegistryUrl,
  allowlistedEcrApiUrl,
  allowlistedEcrBlobRedirect,
  allowlistedEcrRegistryUrl,
  allowlistedGcrBlobRedirect,
  allowlistedGcrRegistryUrl,
  allowlistedGhcrBlobRedirect,
  allowlistedGhcrUrl,
  allowlistedQuayAuthUrl,
  allowlistedQuayBlobRedirect,
  allowlistedQuayRegistryUrl,
  acrBlobUrl,
  acrManifestUrl,
  acrOauthExchangeUrl,
  acrOauthTokenUrl,
  acrRegistryHost,
  dockerhubBlobUrl,
  dockerhubManifestUrl,
  dockerhubTokenUrl,
  ecrApiUrl,
  ecrBlobUrl,
  ecrManifestUrl,
  ecrRegistryHost,
  gcrBlobUrl,
  gcrManifestUrl,
  gcrRegistryHost,
  gcrTokenUrl,
  ghcrBlobUrl,
  ghcrManifestUrl,
  ghcrTokenUrl,
  isAcrRegistryHost,
  isDockerhubAuthHost,
  isDockerhubRegistryHost,
  isEcrApiHost,
  isEcrBlobS3Host,
  isEcrRegistryHost,
  isGcrRegistryHost,
  isGhcrRegistryHost,
  isQuayAuthHost,
  isQuayRegistryHost,
  quayBlobUrl,
  quayManifestUrl,
  quayTokenUrl,
  refuseTenantWritableRegistry,
} from './container.egress';

const DIGEST = `sha256:${'a'.repeat(64)}`;

describe('allowlistedGhcrUrl', () => {
  it('accepts ghcr.io over https/443 for /v2 and /token', () => {
    expect(allowlistedGhcrUrl(`https://ghcr.io/v2/acme/app/manifests/${DIGEST}`)).toBe(
      `https://ghcr.io/v2/acme/app/manifests/${DIGEST}`,
    );
    expect(allowlistedGhcrUrl('https://ghcr.io/token?service=ghcr.io')).toBe(
      'https://ghcr.io/token?service=ghcr.io',
    );
  });

  it('refuses Docker Hub, ECR, GCR, ACR, and GitHub API hosts', () => {
    expect(() => allowlistedGhcrUrl('https://docker.io/v2/library/nginx/manifests/latest')).toThrow(
      /only ghcr\.io/,
    );
    expect(() =>
      allowlistedGhcrUrl('https://123.dkr.ecr.us-east-1.amazonaws.com/v2/app/manifests/sha256:abc'),
    ).toThrow(/only ghcr\.io/);
    expect(() => allowlistedGhcrUrl('https://gcr.io/v2/proj/app/manifests/latest')).toThrow(/only ghcr\.io/);
    expect(() => allowlistedGhcrUrl('https://myregistry.azurecr.io/v2/app/manifests/latest')).toThrow(
      /only ghcr\.io/,
    );
    expect(() => allowlistedGhcrUrl('https://api.github.com/orgs/acme/packages')).toThrow(/only ghcr\.io/);
  });

  it('refuses suffix-confusion, http, userinfo, and non-default ports', () => {
    expect(() => allowlistedGhcrUrl('https://ghcr.io.evil.example/v2/acme/app/manifests/x')).toThrow(
      /only ghcr\.io/,
    );
    expect(() => allowlistedGhcrUrl('http://ghcr.io/v2/acme/app/manifests/x')).toThrow(/non-https/);
    expect(() => allowlistedGhcrUrl('https://user:pass@ghcr.io/v2/acme/app/manifests/x')).toThrow(/userinfo/);
    expect(() => allowlistedGhcrUrl('https://ghcr.io:8443/v2/acme/app/manifests/x')).toThrow(/port/);
  });
});

describe('isGhcrRegistryHost', () => {
  it('accepts only ghcr.io', () => {
    expect(isGhcrRegistryHost('ghcr.io')).toBe(true);
    expect(isGhcrRegistryHost('GHCR.IO')).toBe(true);
    expect(isGhcrRegistryHost('ghcr.io.')).toBe(true);
    expect(isGhcrRegistryHost('docker.io')).toBe(false);
    expect(isGhcrRegistryHost('pkg-containers.githubusercontent.com')).toBe(false);
  });
});

describe('ghcrManifestUrl / ghcrBlobUrl / ghcrTokenUrl', () => {
  it(`builds registry URLs on ${GHCR_REGISTRY_HOST} only`, () => {
    expect(ghcrManifestUrl('acme', 'payments-api', DIGEST)).toBe(
      `https://ghcr.io/v2/acme/payments-api/manifests/${DIGEST}`,
    );
    expect(ghcrBlobUrl('acme', 'foo/bar', DIGEST)).toBe(`https://ghcr.io/v2/acme/foo/bar/blobs/${DIGEST}`);
    expect(ghcrTokenUrl('acme', 'payments-api')).toContain('https://ghcr.io/token?');
    expect(ghcrTokenUrl('acme', 'payments-api')).toContain(encodeURIComponent('repository:acme/payments-api:pull'));
  });
});

describe('allowlistedGhcrBlobRedirect', () => {
  it('allows the GitHub package CDN and ghcr.io, refuses everything else', () => {
    expect(allowlistedGhcrBlobRedirect('https://pkg-containers.githubusercontent.com/ghcr1/blob')).toBe(
      'https://pkg-containers.githubusercontent.com/ghcr1/blob',
    );
    expect(allowlistedGhcrBlobRedirect(`https://ghcr.io/v2/acme/app/blobs/${DIGEST}`)).toContain('ghcr.io');
    expect(() => allowlistedGhcrBlobRedirect('https://evil.example/blob')).toThrow(/redirect host/);
    expect(() => allowlistedGhcrBlobRedirect('https://docker.io/v2/library/nginx/blobs/sha256:x')).toThrow(
      /redirect host/,
    );
  });
});

describe('refuseTenantWritableRegistry', () => {
  it('allows owner/package/digest identity fields', () => {
    expect(() =>
      refuseTenantWritableRegistry({ owner: 'acme', package: 'app', digest: DIGEST }),
    ).not.toThrow();
  });

  it('refuses tenant-writable registry hosts including registryUrl and ghcrUrl', () => {
    expect(() => refuseTenantWritableRegistry({ owner: 'acme', registryUrl: 'https://ghcr.io' })).toThrow(
      /tenant-writable/,
    );
    expect(() => refuseTenantWritableRegistry({ owner: 'acme', ghcrUrl: 'https://ghcr.io/v2/' })).toThrow(
      /tenant-writable/,
    );
    expect(() => refuseTenantWritableRegistry({ owner: 'acme', endpoint: 'https://docker.io' })).toThrow(
      /tenant-writable/,
    );
    expect(() => refuseTenantWritableRegistry({ owner: 'https://evil.example' })).toThrow(/tenant-writable/);
  });

  it('refuses ECR/AWS tenant registry fields and a URL-shaped region', () => {
    expect(() =>
      refuseTenantWritableRegistry({
        region: 'us-east-1',
        ecrHost: '123456789012.dkr.ecr.us-east-1.amazonaws.com',
      }),
    ).toThrow(/tenant-writable/);
    expect(() =>
      refuseTenantWritableRegistry({
        region: 'us-east-1',
        proxyEndpoint: 'https://123456789012.dkr.ecr.us-east-1.amazonaws.com',
      }),
    ).toThrow(/tenant-writable/);
    expect(() =>
      refuseTenantWritableRegistry({
        region: 'us-east-1',
        awsEndpoint: 'https://api.ecr.us-east-1.amazonaws.com',
      }),
    ).toThrow(/tenant-writable/);
    expect(() => refuseTenantWritableRegistry({ region: 'https://evil.example' })).toThrow(/region is an id/);
    expect(() =>
      refuseTenantWritableRegistry({ region: 'us-east-1', accountId: '123456789012' }),
    ).not.toThrow();
  });

  it('refuses tenant pkg.dev / GCR registry URL override fields', () => {
    expect(() =>
      refuseTenantWritableRegistry({
        location: 'us-central1',
        pkgDevHost: 'us-central1-docker.pkg.dev',
      }),
    ).toThrow(/tenant-writable/);
    expect(() =>
      refuseTenantWritableRegistry({
        location: 'us-central1',
        pkgDevUrl: 'https://us-central1-docker.pkg.dev/acme-prod/app',
      }),
    ).toThrow(/tenant-writable/);
    expect(() =>
      refuseTenantWritableRegistry({
        location: 'us-central1',
        registryUrl: 'https://us-central1-docker.pkg.dev',
      }),
    ).toThrow(/tenant-writable/);
    expect(() =>
      refuseTenantWritableRegistry({ location: 'https://us-central1-docker.pkg.dev' }),
    ).toThrow(/location is an id/);
    expect(() =>
      refuseTenantWritableRegistry({ location: 'us-central1-docker.pkg.dev' }),
    ).toThrow(/location is an id/);
    expect(() =>
      refuseTenantWritableRegistry({
        projectId: 'acme-prod',
        location: 'us-central1',
        repository: 'payments-api',
      }),
    ).not.toThrow();
  });

  it('refuses tenant azurecr.io / loginServer URL override fields and allows ACR ids', () => {
    expect(() =>
      refuseTenantWritableRegistry({
        registry: 'acmeprod',
        azurecrUrl: 'https://acmeprod.azurecr.io',
      }),
    ).toThrow(/tenant-writable/);
    expect(() =>
      refuseTenantWritableRegistry({
        registry: 'acmeprod',
        azurecrHost: 'acmeprod.azurecr.io',
      }),
    ).toThrow(/tenant-writable/);
    expect(() =>
      refuseTenantWritableRegistry({
        registry: 'acmeprod',
        acrHost: 'acmeprod.azurecr.io',
      }),
    ).toThrow(/tenant-writable/);
    expect(() =>
      refuseTenantWritableRegistry({
        registry: 'acmeprod',
        loginServer: 'https://acmeprod.azurecr.io',
      }),
    ).toThrow(/loginServer/);
    expect(() =>
      refuseTenantWritableRegistry({
        registry: 'acmeprod',
        loginServer: 'acmeprod.azurecr.io.evil.example',
      }),
    ).toThrow(/loginServer/);
    expect(() => refuseTenantWritableRegistry({ registry: 'https://acmeprod.azurecr.io' })).toThrow(
      /registry is an id/,
    );
    expect(() => refuseTenantWritableRegistry({ registry: 'acmeprod.azurecr.io' })).toThrow(
      /registry is an id/,
    );
    expect(() =>
      refuseTenantWritableRegistry({
        subscriptionId: '11111111-1111-1111-1111-111111111111',
        resourceGroup: 'rg-prod',
        registry: 'acmeprod',
        loginServer: 'acmeprod.azurecr.io',
        repository: 'payments-api',
      }),
    ).not.toThrow();
  });

  it('refuses tenant Docker Hub registry / index / auth URL override fields and allows ids', () => {
    expect(() =>
      refuseTenantWritableRegistry({
        namespace: 'acme',
        registryUrl: 'https://registry-1.docker.io',
      }),
    ).toThrow(/tenant-writable/);
    expect(() =>
      refuseTenantWritableRegistry({
        namespace: 'acme',
        dockerhubUrl: 'https://hub.docker.com',
      }),
    ).toThrow(/tenant-writable/);
    expect(() =>
      refuseTenantWritableRegistry({
        namespace: 'acme',
        index: 'docker.io',
      }),
    ).toThrow(/tenant-writable/);
    expect(() =>
      refuseTenantWritableRegistry({
        namespace: 'acme',
        indexUrl: 'https://index.docker.io/v1/',
      }),
    ).toThrow(/tenant-writable/);
    expect(() =>
      refuseTenantWritableRegistry({
        namespace: 'acme',
        dockerIoHost: 'registry-1.docker.io',
      }),
    ).toThrow(/tenant-writable/);
    expect(() =>
      refuseTenantWritableRegistry({
        namespace: 'acme',
        authUrl: 'https://auth.docker.io/token',
      }),
    ).toThrow(/tenant-writable/);
    expect(() => refuseTenantWritableRegistry({ namespace: 'https://registry-1.docker.io' })).toThrow(
      /namespace is an id/,
    );
    expect(() => refuseTenantWritableRegistry({ namespace: 'registry-1.docker.io' })).toThrow(
      /namespace is an id/,
    );
    expect(() => refuseTenantWritableRegistry({ namespace: 'index.docker.io' })).toThrow(
      /namespace is an id/,
    );
    expect(() =>
      refuseTenantWritableRegistry({
        namespace: 'acme',
        repository: 'payments-api',
        digest: DIGEST,
      }),
    ).not.toThrow();
  });

  it('refuses tenant Quay registry / self-hosted URL override fields and allows ids', () => {
    expect(() =>
      refuseTenantWritableRegistry({
        namespace: 'acme',
        quayUrl: 'https://quay.io',
      }),
    ).toThrow(/tenant-writable/);
    expect(() =>
      refuseTenantWritableRegistry({
        namespace: 'acme',
        quayHost: 'quay.acme.example',
      }),
    ).toThrow(/tenant-writable/);
    expect(() =>
      refuseTenantWritableRegistry({
        namespace: 'acme',
        host: 'quay.enterprise.example',
      }),
    ).toThrow(/tenant-writable/);
    expect(() =>
      refuseTenantWritableRegistry({
        namespace: 'acme',
        baseUrl: 'https://registry.internal',
      }),
    ).toThrow(/tenant-writable/);
    expect(() =>
      refuseTenantWritableRegistry({
        namespace: 'acme',
        authority: 'quay.acme.example',
      }),
    ).toThrow(/tenant-writable/);
    expect(() =>
      refuseTenantWritableRegistry({
        namespace: 'acme',
        selfHosted: true,
      }),
    ).toThrow(/tenant-writable/);
    expect(() =>
      refuseTenantWritableRegistry({
        namespace: 'acme',
        enterpriseUrl: 'https://quay.acme.example',
      }),
    ).toThrow(/tenant-writable/);
    expect(() => refuseTenantWritableRegistry({ namespace: 'https://quay.io' })).toThrow(
      /namespace is an id/,
    );
    expect(() => refuseTenantWritableRegistry({ namespace: 'quay.io' })).toThrow(
      /namespace is an id/,
    );
    expect(() => refuseTenantWritableRegistry({ namespace: 'cdn.quay.io' })).toThrow(
      /namespace is an id/,
    );
    expect(() =>
      refuseTenantWritableRegistry({
        namespace: 'acme',
        repository: 'payments-api',
        digest: DIGEST,
      }),
    ).not.toThrow();
  });
});

const ACCOUNT = '123456789012';
const REGION = 'us-east-1';

describe('allowlistedEcrApiUrl / ecrApiUrl', () => {
  it('accepts api.ecr.{region}.amazonaws.com including GovCloud', () => {
    expect(allowlistedEcrApiUrl('https://api.ecr.us-east-1.amazonaws.com/')).toBe(
      'https://api.ecr.us-east-1.amazonaws.com/',
    );
    expect(ecrApiUrl('us-gov-west-1')).toBe('https://api.ecr.us-gov-west-1.amazonaws.com/');
  });

  it('refuses dkr.ecr, Docker Hub, GHCR, and lookalikes for the signed API', () => {
    expect(() =>
      allowlistedEcrApiUrl('https://123456789012.dkr.ecr.us-east-1.amazonaws.com/v2/'),
    ).toThrow(/only api\.ecr/);
    expect(() => allowlistedEcrApiUrl('https://ghcr.io/v2/acme/app/manifests/x')).toThrow(
      /only amazonaws\.com|only api\.ecr/,
    );
    expect(() => allowlistedEcrApiUrl('https://docker.io/v2/library/nginx/manifests/latest')).toThrow();
    expect(() =>
      allowlistedEcrApiUrl('https://api.ecr.us-east-1.amazonaws.com.evil.example/'),
    ).toThrow(/only amazonaws\.com/);
    expect(() => ecrApiUrl('https://evil.example')).toThrow(/region/);
  });
});

describe('isEcrApiHost / isEcrRegistryHost', () => {
  it('pins API vs registry hosts and refuses suffix confusion', () => {
    expect(isEcrApiHost('api.ecr.us-east-1.amazonaws.com')).toBe(true);
    expect(isEcrApiHost('123456789012.dkr.ecr.us-east-1.amazonaws.com')).toBe(false);
    expect(isEcrRegistryHost('123456789012.dkr.ecr.us-east-1.amazonaws.com', ACCOUNT, REGION)).toBe(
      true,
    );
    expect(isEcrRegistryHost('999999999999.dkr.ecr.us-east-1.amazonaws.com', ACCOUNT, REGION)).toBe(
      false,
    );
    expect(isEcrRegistryHost('123456789012.dkr.ecr.eu-west-1.amazonaws.com', ACCOUNT, REGION)).toBe(
      false,
    );
    expect(isEcrRegistryHost('123456789012.dkr.ecr.us-east-1.amazonaws.com.evil.example')).toBe(false);
    expect(isEcrRegistryHost('ghcr.io')).toBe(false);
  });
});

describe('allowlistedEcrRegistryUrl / ecrManifestUrl', () => {
  it('builds the account+region dkr.ecr host from ids, never a tenant URL', () => {
    expect(ecrRegistryHost(ACCOUNT, REGION)).toBe(`${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com`);
    expect(ecrManifestUrl(ACCOUNT, REGION, 'payments-api', DIGEST)).toBe(
      `https://${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com/v2/payments-api/manifests/${DIGEST}`,
    );
    expect(ecrBlobUrl(ACCOUNT, REGION, 'team/app', DIGEST)).toBe(
      `https://${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com/v2/team/app/blobs/${DIGEST}`,
    );
    expect(() =>
      allowlistedEcrRegistryUrl(
        'https://999999999999.dkr.ecr.us-east-1.amazonaws.com/v2/app/manifests/sha256:abc',
        ACCOUNT,
        REGION,
      ),
    ).toThrow(/only 123456789012\.dkr\.ecr/);
    expect(() =>
      allowlistedEcrRegistryUrl('https://ghcr.io/v2/acme/app/manifests/sha256:abc', ACCOUNT, REGION),
    ).toThrow();
    expect(() =>
      allowlistedEcrRegistryUrl(
        `http://${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com/v2/app/manifests/${DIGEST}`,
        ACCOUNT,
        REGION,
      ),
    ).toThrow(/non-https/);
  });
});

describe('allowlistedEcrBlobRedirect', () => {
  it('allows the same dkr.ecr host and regional S3, refuses everything else', () => {
    expect(
      allowlistedEcrBlobRedirect(
        `https://${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com/v2/app/blobs/${DIGEST}`,
        ACCOUNT,
        REGION,
      ),
    ).toContain('dkr.ecr');
    expect(
      allowlistedEcrBlobRedirect(
        'https://prod-us-east-1-starport-layer-bucket.s3.us-east-1.amazonaws.com/blob?X-Amz-Signature=1',
        ACCOUNT,
        REGION,
      ),
    ).toContain('s3.us-east-1.amazonaws.com');
    expect(isEcrBlobS3Host('prod-us-east-1-starport-layer-bucket.s3.us-east-1.amazonaws.com', REGION)).toBe(
      true,
    );
    expect(() => allowlistedEcrBlobRedirect('https://docker.io/v2/library/nginx/blobs/x', ACCOUNT, REGION)).toThrow(
      /redirect host/,
    );
    expect(() => allowlistedEcrBlobRedirect('https://ghcr.io/v2/acme/app/blobs/x', ACCOUNT, REGION)).toThrow(
      /redirect host/,
    );
    expect(() => allowlistedEcrBlobRedirect('https://evil.example/blob', ACCOUNT, REGION)).toThrow(
      /redirect host/,
    );
  });
});

const PROJECT = 'acme-prod';
const GCR_LOCATION = 'us-central1';

describe('gcrRegistryHost / isGcrRegistryHost', () => {
  it('derives {location}-docker.pkg.dev from a location id and pins the exact host', () => {
    expect(gcrRegistryHost(GCR_LOCATION)).toBe('us-central1-docker.pkg.dev');
    expect(gcrRegistryHost('us')).toBe('us-docker.pkg.dev');
    expect(isGcrRegistryHost('us-central1-docker.pkg.dev', GCR_LOCATION)).toBe(true);
    expect(isGcrRegistryHost('US-CENTRAL1-DOCKER.PKG.DEV', GCR_LOCATION)).toBe(true);
    expect(isGcrRegistryHost('us-docker.pkg.dev', GCR_LOCATION)).toBe(false);
    expect(isGcrRegistryHost('us-central1-docker.pkg.dev.evil.example', GCR_LOCATION)).toBe(false);
    expect(isGcrRegistryHost('docker.pkg.dev', GCR_LOCATION)).toBe(false);
    expect(isGcrRegistryHost('pkg.dev', GCR_LOCATION)).toBe(false);
    expect(isGcrRegistryHost('gcr.io', GCR_LOCATION)).toBe(false);
    expect(isGcrRegistryHost('ghcr.io', GCR_LOCATION)).toBe(false);
  });
});

describe('allowlistedGcrRegistryUrl / gcrManifestUrl', () => {
  it('builds the location docker.pkg.dev host from ids, never a tenant URL', () => {
    expect(gcrManifestUrl(GCR_LOCATION, PROJECT, 'payments-api', 'web', DIGEST)).toBe(
      `https://us-central1-docker.pkg.dev/v2/${PROJECT}/payments-api/web/manifests/${DIGEST}`,
    );
    expect(gcrBlobUrl(GCR_LOCATION, PROJECT, 'payments-api', 'web/api', DIGEST)).toBe(
      `https://us-central1-docker.pkg.dev/v2/${PROJECT}/payments-api/web/api/blobs/${DIGEST}`,
    );
    expect(gcrTokenUrl(GCR_LOCATION, PROJECT, 'payments-api', 'web')).toContain(
      'https://us-central1-docker.pkg.dev/v2/token?',
    );
    expect(() =>
      allowlistedGcrRegistryUrl(
        'https://europe-west1-docker.pkg.dev/v2/acme-prod/app/manifests/sha256:abc',
        GCR_LOCATION,
      ),
    ).toThrow(/only us-central1-docker\.pkg\.dev/);
    expect(() =>
      allowlistedGcrRegistryUrl('https://us-central1-docker.pkg.dev.evil.example/v2/app/manifests/x', GCR_LOCATION),
    ).toThrow(/only us-central1-docker\.pkg\.dev/);
    expect(() =>
      allowlistedGcrRegistryUrl('https://ghcr.io/v2/acme/app/manifests/sha256:abc', GCR_LOCATION),
    ).toThrow();
    expect(() =>
      allowlistedGcrRegistryUrl(
        `http://us-central1-docker.pkg.dev/v2/${PROJECT}/payments-api/web/manifests/${DIGEST}`,
        GCR_LOCATION,
      ),
    ).toThrow(/non-https/);
    expect(() => gcrRegistryHost('https://evil.example')).toThrow(/location/);
    expect(() => gcrRegistryHost('us-central1-docker.pkg.dev')).toThrow(/location/);
  });
});

describe('allowlistedGcrBlobRedirect', () => {
  it('allows the pinned docker.pkg.dev host and path-style GCS, refuses suffix confusion', () => {
    expect(
      allowlistedGcrBlobRedirect(
        `https://us-central1-docker.pkg.dev/v2/${PROJECT}/payments-api/web/blobs/${DIGEST}`,
        GCR_LOCATION,
      ),
    ).toContain('us-central1-docker.pkg.dev');
    expect(
      allowlistedGcrBlobRedirect(
        'https://storage.googleapis.com/artifacts-acme/containers/images/blob?sig=1',
        GCR_LOCATION,
      ),
    ).toContain('storage.googleapis.com');
    expect(() =>
      allowlistedGcrBlobRedirect('https://us-central1-docker.pkg.dev.evil.example/blob', GCR_LOCATION),
    ).toThrow(/redirect host/);
    expect(() => allowlistedGcrBlobRedirect('https://docker.io/v2/library/nginx/blobs/x', GCR_LOCATION)).toThrow(
      /redirect host/,
    );
    expect(() => allowlistedGcrBlobRedirect('https://ghcr.io/v2/acme/app/blobs/x', GCR_LOCATION)).toThrow(
      /redirect host/,
    );
    expect(() =>
      allowlistedGcrBlobRedirect('https://acme.azurecr.io/v2/app/blobs/x', GCR_LOCATION),
    ).toThrow(/redirect host/);
  });
});

const ACR_REGISTRY = 'acmeprod';

describe('acrRegistryHost / isAcrRegistryHost', () => {
  it('derives {registry}.azurecr.io from a registry id and pins the exact host', () => {
    expect(acrRegistryHost(ACR_REGISTRY)).toBe('acmeprod.azurecr.io');
    expect(acrRegistryHost('AcmeProd')).toBe('acmeprod.azurecr.io');
    expect(isAcrRegistryHost('acmeprod.azurecr.io', ACR_REGISTRY)).toBe(true);
    expect(isAcrRegistryHost('ACMEPROD.AZURECR.IO', ACR_REGISTRY)).toBe(true);
    expect(isAcrRegistryHost('otherreg.azurecr.io', ACR_REGISTRY)).toBe(false);
    expect(isAcrRegistryHost('acmeprod.azurecr.io.evil.example', ACR_REGISTRY)).toBe(false);
    expect(isAcrRegistryHost('acmeprod.eastus.data.azurecr.io', ACR_REGISTRY)).toBe(false);
    expect(isAcrRegistryHost('acmeprod.azurecr.cn', ACR_REGISTRY)).toBe(false);
    expect(isAcrRegistryHost('azurecr.io', ACR_REGISTRY)).toBe(false);
    expect(isAcrRegistryHost('ghcr.io', ACR_REGISTRY)).toBe(false);
  });
});

describe('allowlistedAcrRegistryUrl / acrManifestUrl', () => {
  it('builds the registry azurecr.io host from ids, never a tenant URL', () => {
    expect(acrManifestUrl(ACR_REGISTRY, 'payments-api', DIGEST)).toBe(
      `https://acmeprod.azurecr.io/v2/payments-api/manifests/${DIGEST}`,
    );
    expect(acrBlobUrl(ACR_REGISTRY, 'team/api', DIGEST)).toBe(
      `https://acmeprod.azurecr.io/v2/team/api/blobs/${DIGEST}`,
    );
    expect(acrOauthExchangeUrl(ACR_REGISTRY)).toBe('https://acmeprod.azurecr.io/oauth2/exchange');
    expect(acrOauthTokenUrl(ACR_REGISTRY)).toBe('https://acmeprod.azurecr.io/oauth2/token');
    expect(() =>
      allowlistedAcrRegistryUrl('https://evilreg.azurecr.io/v2/app/manifests/sha256:abc', ACR_REGISTRY),
    ).toThrow(/only acmeprod\.azurecr\.io/);
    expect(() =>
      allowlistedAcrRegistryUrl('https://acmeprod.azurecr.io.evil.example/v2/app/manifests/x', ACR_REGISTRY),
    ).toThrow(/only acmeprod\.azurecr\.io/);
    expect(() =>
      allowlistedAcrRegistryUrl('https://ghcr.io/v2/acme/app/manifests/sha256:abc', ACR_REGISTRY),
    ).toThrow();
    expect(() =>
      allowlistedAcrRegistryUrl(`http://acmeprod.azurecr.io/v2/app/manifests/${DIGEST}`, ACR_REGISTRY),
    ).toThrow(/non-https/);
    expect(() => acrRegistryHost('https://evil.example')).toThrow(/registry/);
    expect(() => acrRegistryHost('acmeprod.azurecr.io')).toThrow(/registry/);
    expect(() =>
      allowlistedAcrOauthUrl('https://acmeprod.azurecr.io/v2/token', ACR_REGISTRY),
    ).toThrow(/oauth2\/exchange/);
  });
});

describe('allowlistedAcrBlobRedirect', () => {
  it('allows the pinned azurecr.io host and refuses suffix confusion / other registries', () => {
    expect(
      allowlistedAcrBlobRedirect(
        `https://acmeprod.azurecr.io/v2/payments-api/blobs/${DIGEST}`,
        ACR_REGISTRY,
      ),
    ).toContain('acmeprod.azurecr.io');
    expect(() =>
      allowlistedAcrBlobRedirect('https://acmeprod.azurecr.io.evil.example/blob', ACR_REGISTRY),
    ).toThrow(/acmeprod\.azurecr\.io/);
    expect(() =>
      allowlistedAcrBlobRedirect('https://acmeprod.eastus.data.azurecr.io/blob', ACR_REGISTRY),
    ).toThrow(/acmeprod\.azurecr\.io/);
    expect(() =>
      allowlistedAcrBlobRedirect('https://docker.io/v2/library/nginx/blobs/x', ACR_REGISTRY),
    ).toThrow(/acmeprod\.azurecr\.io/);
    expect(() =>
      allowlistedAcrBlobRedirect('https://ghcr.io/v2/acme/app/blobs/x', ACR_REGISTRY),
    ).toThrow(/acmeprod\.azurecr\.io/);
    expect(() =>
      allowlistedAcrBlobRedirect(
        'https://us-central1-docker.pkg.dev/v2/acme/app/blobs/x',
        ACR_REGISTRY,
      ),
    ).toThrow(/acmeprod\.azurecr\.io/);
  });
});

describe('isDockerhubRegistryHost / isDockerhubAuthHost', () => {
  it('pins exact registry-1.docker.io and auth.docker.io hosts', () => {
    expect(isDockerhubRegistryHost('registry-1.docker.io')).toBe(true);
    expect(isDockerhubRegistryHost('REGISTRY-1.DOCKER.IO')).toBe(true);
    expect(isDockerhubRegistryHost('registry-1.docker.io.')).toBe(true);
    expect(isDockerhubRegistryHost('registry-1.docker.io.evil.example')).toBe(false);
    expect(isDockerhubRegistryHost('docker.io')).toBe(false);
    expect(isDockerhubRegistryHost('index.docker.io')).toBe(false);
    expect(isDockerhubRegistryHost('hub.docker.com')).toBe(false);
    expect(isDockerhubRegistryHost('auth.docker.io')).toBe(false);
    expect(isDockerhubAuthHost('auth.docker.io')).toBe(true);
    expect(isDockerhubAuthHost('AUTH.DOCKER.IO')).toBe(true);
    expect(isDockerhubAuthHost('auth.docker.io.evil.example')).toBe(false);
    expect(isDockerhubAuthHost('hub.docker.com')).toBe(false);
    expect(isDockerhubAuthHost('registry-1.docker.io')).toBe(false);
  });
});

describe('allowlistedDockerhubRegistryUrl / dockerhubManifestUrl', () => {
  it('builds registry-1.docker.io URLs from namespace/repository ids, never a tenant URL', () => {
    expect(dockerhubManifestUrl('acme', 'payments-api', DIGEST)).toBe(
      `https://registry-1.docker.io/v2/acme/payments-api/manifests/${DIGEST}`,
    );
    expect(dockerhubBlobUrl('library', 'ubuntu', DIGEST)).toBe(
      `https://registry-1.docker.io/v2/library/ubuntu/blobs/${DIGEST}`,
    );
    expect(dockerhubTokenUrl('acme', 'payments-api')).toBe(
      'https://auth.docker.io/token?service=registry.docker.io&scope=repository%3Aacme%2Fpayments-api%3Apull',
    );
    expect(() =>
      allowlistedDockerhubRegistryUrl('https://docker.io/v2/library/nginx/manifests/sha256:abc'),
    ).toThrow(/only registry-1\.docker\.io/);
    expect(() =>
      allowlistedDockerhubRegistryUrl('https://index.docker.io/v2/acme/app/manifests/x'),
    ).toThrow(/only registry-1\.docker\.io/);
    expect(() =>
      allowlistedDockerhubRegistryUrl('https://registry-1.docker.io.evil.example/v2/app/manifests/x'),
    ).toThrow(/only registry-1\.docker\.io/);
    expect(() =>
      allowlistedDockerhubRegistryUrl('https://hub.docker.com/v2/repositories/acme/app'),
    ).toThrow(/only registry-1\.docker\.io/);
    expect(() =>
      allowlistedDockerhubRegistryUrl(`http://registry-1.docker.io/v2/acme/app/manifests/${DIGEST}`),
    ).toThrow(/non-https/);
    expect(() =>
      allowlistedDockerhubAuthUrl('https://hub.docker.com/v2/users/login'),
    ).toThrow(/only auth\.docker\.io/);
    expect(() =>
      allowlistedDockerhubAuthUrl('https://auth.docker.io/v2/token'),
    ).toThrow(/only \/token/);
  });
});

describe('allowlistedDockerhubBlobRedirect', () => {
  it('allows the pinned registry-1.docker.io host and refuses CDN / other registries', () => {
    expect(
      allowlistedDockerhubBlobRedirect(`https://registry-1.docker.io/v2/acme/payments-api/blobs/${DIGEST}`),
    ).toContain('registry-1.docker.io');
    expect(() =>
      allowlistedDockerhubBlobRedirect('https://production.cloudflare.docker.com/registry-v2/blobs/x'),
    ).toThrow(/registry-1\.docker\.io/);
    expect(() =>
      allowlistedDockerhubBlobRedirect('https://registry-1.docker.io.evil.example/blob'),
    ).toThrow(/registry-1\.docker\.io/);
    expect(() => allowlistedDockerhubBlobRedirect('https://docker.io/v2/library/nginx/blobs/x')).toThrow(
      /registry-1\.docker\.io/,
    );
    expect(() => allowlistedDockerhubBlobRedirect('https://index.docker.io/v1/')).toThrow(
      /registry-1\.docker\.io/,
    );
    expect(() => allowlistedDockerhubBlobRedirect('https://ghcr.io/v2/acme/app/blobs/x')).toThrow(
      /registry-1\.docker\.io/,
    );
    expect(() =>
      allowlistedDockerhubBlobRedirect('https://acmeprod.azurecr.io/v2/app/blobs/x'),
    ).toThrow(/registry-1\.docker\.io/);
  });
});

describe('isQuayRegistryHost / isQuayAuthHost', () => {
  it('pins exact quay.io and refuses suffix confusion / self-hosted hosts', () => {
    expect(isQuayRegistryHost('quay.io')).toBe(true);
    expect(isQuayRegistryHost('QUAY.IO')).toBe(true);
    expect(isQuayRegistryHost('quay.io.')).toBe(true);
    expect(isQuayRegistryHost('quay.io.evil.example')).toBe(false);
    expect(isQuayRegistryHost('cdn.quay.io')).toBe(false);
    expect(isQuayRegistryHost('www.quay.io')).toBe(false);
    expect(isQuayRegistryHost('notquay.io')).toBe(false);
    expect(isQuayRegistryHost('quay.example.com')).toBe(false);
    expect(isQuayRegistryHost('ghcr.io')).toBe(false);
    expect(isQuayAuthHost('quay.io')).toBe(true);
    expect(isQuayAuthHost('cdn.quay.io')).toBe(false);
  });
});

describe('allowlistedQuayRegistryUrl / quayManifestUrl', () => {
  it('builds quay.io URLs from namespace/repository ids, never a tenant URL', () => {
    expect(quayManifestUrl('acme', 'payments-api', DIGEST)).toBe(
      `https://quay.io/v2/acme/payments-api/manifests/${DIGEST}`,
    );
    expect(quayBlobUrl('acme', 'team/api', DIGEST)).toBe(
      `https://quay.io/v2/acme/team/api/blobs/${DIGEST}`,
    );
    expect(quayTokenUrl('acme', 'payments-api')).toBe(
      'https://quay.io/v2/auth?service=quay.io&scope=repository%3Aacme%2Fpayments-api%3Apull',
    );
    expect(() =>
      allowlistedQuayRegistryUrl('https://cdn.quay.io/v2/acme/app/manifests/sha256:abc'),
    ).toThrow(/only quay\.io/);
    expect(() =>
      allowlistedQuayRegistryUrl('https://quay.io.evil.example/v2/app/manifests/x'),
    ).toThrow(/only quay\.io/);
    expect(() =>
      allowlistedQuayRegistryUrl('https://quay.acme.example/v2/acme/app/manifests/x'),
    ).toThrow(/only quay\.io/);
    expect(() =>
      allowlistedQuayRegistryUrl('https://ghcr.io/v2/acme/app/manifests/sha256:abc'),
    ).toThrow(/only quay\.io/);
    expect(() =>
      allowlistedQuayRegistryUrl(`http://quay.io/v2/acme/app/manifests/${DIGEST}`),
    ).toThrow(/non-https/);
    expect(() => allowlistedQuayAuthUrl('https://quay.io/token')).toThrow(/only \/v2\/auth/);
    expect(() => allowlistedQuayAuthUrl('https://quay.io/api/v1/repository')).toThrow(
      /only \/v2\/auth/,
    );
    expect(() => allowlistedQuayAuthUrl('https://quay.acme.example/v2/auth')).toThrow(
      /only quay\.io/,
    );
  });
});

describe('allowlistedQuayBlobRedirect', () => {
  it('allows the pinned quay.io host and refuses CDN / self-hosted / other registries', () => {
    expect(
      allowlistedQuayBlobRedirect(`https://quay.io/v2/acme/payments-api/blobs/${DIGEST}`),
    ).toContain('quay.io');
    expect(() =>
      allowlistedQuayBlobRedirect('https://cdn.quay.io/v2/acme/payments-api/blobs/x'),
    ).toThrow(/quay\.io/);
    expect(() =>
      allowlistedQuayBlobRedirect('https://quay.io.evil.example/blob'),
    ).toThrow(/quay\.io/);
    expect(() =>
      allowlistedQuayBlobRedirect('https://quay.acme.example/v2/acme/app/blobs/x'),
    ).toThrow(/quay\.io/);
    expect(() => allowlistedQuayBlobRedirect('https://ghcr.io/v2/acme/app/blobs/x')).toThrow(
      /quay\.io/,
    );
    expect(() =>
      allowlistedQuayBlobRedirect('https://registry-1.docker.io/v2/acme/app/blobs/x'),
    ).toThrow(/quay\.io/);
    expect(() =>
      allowlistedQuayBlobRedirect('https://acmeprod.azurecr.io/v2/app/blobs/x'),
    ).toThrow(/quay\.io/);
  });
});

