import { describe, expect, it } from 'vitest';
import { AZURE_ARM_HOST } from './azure.egress';
import {
  EXTRA_HOST_KEY_RE,
  TENANT_ENDPOINT_KEYS,
  aksClustersUrl,
  allowlistedEksApiUrl,
  allowlistedGkeApiUrl,
  eksApiUrl,
  eksClustersUrl,
  eksDescribeClusterUrl,
  gkeClustersUrl,
  isEksApiHost,
  isGkeApiHost,
  refuseTenantWritableEndpoint,
} from './kubernetes.egress';

const SUB = '11111111-1111-1111-1111-111111111111';

describe('allowlistedEksApiUrl', () => {
  it('accepts commercial and GovCloud EKS management hosts', () => {
    expect(allowlistedEksApiUrl('https://api.eks.us-east-1.amazonaws.com/')).toBe(
      'https://api.eks.us-east-1.amazonaws.com/',
    );
    expect(allowlistedEksApiUrl('https://api.eks.us-gov-west-1.amazonaws.com/clusters')).toBe(
      'https://api.eks.us-gov-west-1.amazonaws.com/clusters',
    );
  });

  it('refuses cluster kube-apiserver hosts, eks-proxy, and lookalikes', () => {
    expect(() =>
      allowlistedEksApiUrl('https://ABCDEF.gr7.us-east-1.eks.amazonaws.com'),
    ).toThrow(/only api\.eks/);
    expect(() =>
      allowlistedEksApiUrl('https://eks-proxy.eks.us-east-1.amazonaws.com/clusters/prod/k8sapi'),
    ).toThrow(/only api\.eks/);
    expect(() => allowlistedEksApiUrl('https://eks.us-east-1.amazonaws.com/')).toThrow(
      /only api\.eks/,
    );
    expect(() => allowlistedEksApiUrl('https://10.0.0.12:6443')).toThrow(/only amazonaws\.com/);
    expect(() => allowlistedEksApiUrl('https://api.eks.us-east-1.amazonaws.com.evil.example/')).toThrow(
      /only amazonaws\.com/,
    );
  });

  it('refuses http, userinfo, and non-default ports', () => {
    expect(() => allowlistedEksApiUrl('http://api.eks.us-east-1.amazonaws.com/')).toThrow(
      /non-https/,
    );
    expect(() =>
      allowlistedEksApiUrl('https://user:pass@api.eks.us-east-1.amazonaws.com/'),
    ).toThrow(/userinfo/);
    expect(() => allowlistedEksApiUrl('https://api.eks.us-east-1.amazonaws.com:8443/')).toThrow(
      /port/,
    );
  });
});

describe('isEksApiHost / isGkeApiHost', () => {
  it('accepts only the control-plane hosts', () => {
    expect(isEksApiHost('api.eks.us-east-1.amazonaws.com')).toBe(true);
    expect(isEksApiHost('ABCDEF.gr7.us-east-1.eks.amazonaws.com')).toBe(false);
    expect(isGkeApiHost('container.googleapis.com')).toBe(true);
    expect(isGkeApiHost('cloudasset.googleapis.com')).toBe(false);
    expect(isGkeApiHost('container.googleapis.com.evil.example')).toBe(false);
  });
});

describe('allowlistedGkeApiUrl', () => {
  it('accepts container.googleapis.com only', () => {
    expect(
      allowlistedGkeApiUrl('https://container.googleapis.com/v1/projects/acme-prod/locations/-/clusters'),
    ).toBe('https://container.googleapis.com/v1/projects/acme-prod/locations/-/clusters');
  });

  it('refuses other Google hosts and tenant kube-apiserver IPs', () => {
    expect(() => allowlistedGkeApiUrl('https://compute.googleapis.com/compute/v1/projects/acme')).toThrow(
      /only container\.googleapis\.com/,
    );
    expect(() => allowlistedGkeApiUrl('https://35.188.1.2/api/v1/namespaces')).toThrow(
      /only googleapis\.com/,
    );
  });
});

describe('platform URL builders', () => {
  it('builds EKS/GKE/AKS control-plane URLs from identifiers', () => {
    expect(eksApiUrl('eu-central-1')).toBe('https://api.eks.eu-central-1.amazonaws.com/');
    expect(eksClustersUrl('us-east-1')).toBe(
      'https://api.eks.us-east-1.amazonaws.com/clusters?maxResults=100',
    );
    expect(eksDescribeClusterUrl('us-east-1', 'prod')).toBe(
      'https://api.eks.us-east-1.amazonaws.com/clusters/prod',
    );
    expect(gkeClustersUrl('acme-prod')).toBe(
      'https://container.googleapis.com/v1/projects/acme-prod/locations/-/clusters?pageSize=100',
    );
    expect(aksClustersUrl(SUB)).toBe(
      `https://${AZURE_ARM_HOST}/subscriptions/${SUB}/providers/Microsoft.ContainerService/managedClusters?api-version=2024-09-01`,
    );
  });

  it('refuses a cluster name or region that is a URL', () => {
    expect(() => eksApiUrl('https://evil.example')).toThrow(/region/);
    expect(() => eksDescribeClusterUrl('us-east-1', 'https://10.0.0.5:6443')).toThrow(
      /cluster name/,
    );
    expect(() => gkeClustersUrl('https://evil.example')).toThrow(/project/);
    expect(() => aksClustersUrl('https://management.azure.com')).toThrow(/subscription/);
  });
});

describe('refuseTenantWritableEndpoint', () => {
  it('allows a cloud + identifier config', () => {
    expect(() => refuseTenantWritableEndpoint({ cloud: 'aws', region: 'us-east-1' })).not.toThrow();
    expect(() =>
      refuseTenantWritableEndpoint({ cloud: 'gcp', projectId: 'acme-prod' }),
    ).not.toThrow();
    expect(() => refuseTenantWritableEndpoint({ cloud: 'azure', subscriptionId: SUB })).not.toThrow();
  });

  it('refuses apiServerUrl, kubeconfig server, and path-as-URL keys', () => {
    expect(() =>
      refuseTenantWritableEndpoint({
        cloud: 'aws',
        region: 'us-east-1',
        apiServerUrl: 'https://10.0.0.12:6443',
      }),
    ).toThrow(/tenant-writable Kubernetes endpoint/);
    expect(() =>
      refuseTenantWritableEndpoint({
        cloud: 'gcp',
        projectId: 'acme-prod',
        kubeconfig: '/tmp/kubeconfig',
      }),
    ).toThrow(/tenant-writable Kubernetes endpoint/);
    expect(() =>
      refuseTenantWritableEndpoint({
        cloud: 'azure',
        subscriptionId: SUB,
        server: 'https://prod.hcp.eastus.azmk8s.io',
      }),
    ).toThrow(/tenant-writable Kubernetes endpoint/);
    expect(() =>
      refuseTenantWritableEndpoint({
        cloud: 'aws',
        region: 'us-east-1',
        kubeconfigPath: 'https://evil.example/kubeconfig',
      }),
    ).toThrow(/tenant-writable Kubernetes endpoint/);
  });

  it('refuses EXTRA_*_HOST_KEYS and the standard host keys', () => {
    expect(EXTRA_HOST_KEY_RE.test('EXTRA_KUBERNETES_HOST_KEYS')).toBe(true);
    expect(() =>
      refuseTenantWritableEndpoint({
        cloud: 'aws',
        region: 'us-east-1',
        EXTRA_KUBERNETES_HOST_KEYS: ['evil.example'],
      }),
    ).toThrow(/EXTRA_\*_HOST_KEYS/);
    expect(() =>
      refuseTenantWritableEndpoint({
        cloud: 'aws',
        region: 'us-east-1',
        EXTRA_AWS_HOST_KEYS: 'https://evil.example',
      }),
    ).toThrow(/EXTRA_\*_HOST_KEYS/);
    for (const key of ['endpoint', 'baseUrl', 'host', 'url'] as const) {
      expect(TENANT_ENDPOINT_KEYS).toContain(key);
      expect(() =>
        refuseTenantWritableEndpoint({ cloud: 'aws', region: 'us-east-1', [key]: 'https://evil.example' }),
      ).toThrow(/tenant-writable Kubernetes endpoint/);
    }
  });

  it('refuses identifier fields that are themselves URLs', () => {
    expect(() => refuseTenantWritableEndpoint({ cloud: 'https://evil.example' })).toThrow(
      /tenant-writable Kubernetes endpoint/,
    );
    expect(() =>
      refuseTenantWritableEndpoint({ cloud: 'aws', region: 'https://api.eks.us-east-1.amazonaws.com' }),
    ).toThrow(/tenant-writable Kubernetes endpoint/);
  });
});
