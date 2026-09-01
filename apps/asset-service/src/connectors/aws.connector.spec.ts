import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  AWS_MAX_PAGES,
  AWS_PER_PAGE,
  AwsConnector,
  bucketToAsset,
  instanceToAsset,
  parseCallerAccount,
  parseEc2Instances,
  type AwsInstance,
} from './aws.connector';
import type { DiscoveryContext } from './connector.registry';

const ACCOUNT = '123456789012';
const REGION = 'us-east-1';

const ctx = (
  config: Record<string, unknown> = { region: REGION },
  credentialRef: string | null = 'env:AWS_ACCESS_KEY_ID',
): DiscoveryContext => ({
  orgId: 'org-1',
  integrationId: 'int-1',
  config,
  credentialRef,
  since: null,
});

async function collect(iter: AsyncIterable<unknown>): Promise<unknown[]> {
  const out: unknown[] = [];
  for await (const item of iter) out.push(item);
  return out;
}

function callerXml(account = ACCOUNT): string {
  return `<GetCallerIdentityResponse><GetCallerIdentityResult><Account>${account}</Account></GetCallerIdentityResult></GetCallerIdentityResponse>`;
}

function instancesXml(ids: string[], nextToken?: string): string {
  const reservations = ids
    .map(
      (id) =>
        `<item><instancesSet><item><instanceId>${id}</instanceId><instanceState><name>running</name></instanceState><privateIpAddress>10.0.0.8</privateIpAddress></item></instancesSet></item>`,
    )
    .join('');
  return `<DescribeInstancesResponse><reservationSet>${reservations}</reservationSet>${
    nextToken ? `<nextToken>${nextToken}</nextToken>` : ''
  }</DescribeInstancesResponse>`;
}

function emptyEc2(action: 'DescribeSecurityGroups' | 'DescribeAddresses'): string {
  return `<${action}Response></${action}Response>`;
}

function bucketsXml(names: string[]): string {
  const buckets = names.map((n) => `<Bucket><Name>${n}</Name></Bucket>`).join('');
  return `<ListAllMyBucketsResult><Buckets>${buckets}</Buckets></ListAllMyBucketsResult>`;
}

function stubAws(opts: {
  instances?: string[][];
  buckets?: string[];
  status?: number;
}): ReturnType<typeof vi.fn> {
  let instancePage = 0;
  const fn = vi.fn(async (url: string | URL, init?: RequestInit) => {
    const href = String(url);
    const body = String(init?.body ?? '');
    if (opts.status && opts.status !== 200) {
      return new Response('boom', { status: opts.status });
    }
    if (href.includes('sts.') && body.includes('GetCallerIdentity')) {
      return new Response(callerXml(), { status: 200 });
    }
    if (href.includes('ec2.') && body.includes('DescribeInstances')) {
      const page = opts.instances?.[instancePage] ?? [];
      const more = opts.instances && instancePage < opts.instances.length - 1;
      instancePage += 1;
      return new Response(instancesXml(page, more ? `page-${instancePage}` : undefined), {
        status: 200,
      });
    }
    if (href.includes('ec2.') && body.includes('DescribeSecurityGroups')) {
      return new Response(emptyEc2('DescribeSecurityGroups'), { status: 200 });
    }
    if (href.includes('ec2.') && body.includes('DescribeAddresses')) {
      return new Response(emptyEc2('DescribeAddresses'), { status: 200 });
    }
    if (href.includes('s3.amazonaws.com')) {
      return new Response(bucketsXml(opts.buckets ?? []), { status: 200 });
    }
    return new Response('unexpected', { status: 500 });
  });
  vi.stubGlobal('fetch', fn);
  return fn;
}

function setAwsCreds(): void {
  process.env.AWS_ACCESS_KEY_ID = 'AKIATEST';
  process.env.AWS_SECRET_ACCESS_KEY = 'secret';
}

afterEach(() => {
  vi.unstubAllGlobals();
  delete process.env.AWS_ACCESS_KEY_ID;
  delete process.env.AWS_SECRET_ACCESS_KEY;
  delete process.env.AWS_SESSION_TOKEN;
});

describe('instanceToAsset / bucketToAsset', () => {
  it('maps identity as cloud_resource', () => {
    const inst: AwsInstance = { instanceId: 'i-abc', publicIp: '1.2.3.4', name: 'web' };
    expect(instanceToAsset(ACCOUNT, REGION, inst)).toMatchObject({
      kind: 'cloud_resource',
      externalKey: `aws:${ACCOUNT}:ec2:${REGION}:i-abc`,
      name: 'web',
      source: 'aws',
      exposure: 'internet_facing',
    });
    expect(bucketToAsset(ACCOUNT, REGION, { name: 'logs' })).toMatchObject({
      kind: 'cloud_resource',
      externalKey: `aws:${ACCOUNT}:s3:logs`,
      source: 'aws',
    });
  });
});

describe('parseCallerAccount / parseEc2Instances', () => {
  it('reads the account and instances from Query XML', () => {
    expect(parseCallerAccount(callerXml())).toBe(ACCOUNT);
    expect(parseEc2Instances(instancesXml(['i-1', 'i-2'])).map((i) => i.instanceId)).toEqual([
      'i-1',
      'i-2',
    ]);
  });
});

describe('AwsConnector.discover', () => {
  it('inventories EC2 and S3 as cloud_resource against allowlisted AWS hosts', async () => {
    setAwsCreds();
    const fetchFn = stubAws({ instances: [['i-aaa']], buckets: ['acme-logs'] });
    const assets = (await collect(new AwsConnector().discover(ctx()))) as Array<{
      kind: string;
      source: string;
      externalKey: string;
    }>;
    expect(assets.every((a) => a.kind === 'cloud_resource')).toBe(true);
    expect(assets.every((a) => a.source === 'aws')).toBe(true);
    expect(assets.map((a) => a.externalKey)).toEqual(
      expect.arrayContaining([
        `aws:${ACCOUNT}:ec2:${REGION}:i-aaa`,
        `aws:${ACCOUNT}:s3:acme-logs`,
      ]),
    );
    for (const [url] of fetchFn.mock.calls) {
      const host = new URL(String(url)).hostname;
      expect(host.endsWith('amazonaws.com')).toBe(true);
      expect(host).not.toContain('evil');
    }
    expect(String(fetchFn.mock.calls[0][0])).toContain('sts.us-east-1.amazonaws.com');
    expect(fetchFn.mock.calls.some(([url]) => String(url).includes('ec2.us-east-1.amazonaws.com'))).toBe(
      true,
    );
    expect(fetchFn.mock.calls.some(([url]) => String(url) === 'https://s3.amazonaws.com/')).toBe(true);
  });

  it('fails closed when AWS_* credentials are missing', async () => {
    const fetchFn = stubAws({ instances: [['i-aaa']] });
    await expect(collect(new AwsConnector().discover(ctx()))).rejects.toThrow(/cannot be used/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('fails closed when credentialRef is unset — no unauthenticated listing', async () => {
    setAwsCreds();
    const fetchFn = stubAws({ instances: [['i-aaa']] });
    await expect(collect(new AwsConnector().discover(ctx({ region: REGION }, null)))).rejects.toThrow(
      /env:AWS_\*/,
    );
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('refuses a tenant-writable endpoint and never sends keys there', async () => {
    setAwsCreds();
    const fetchFn = stubAws({ instances: [['i-aaa']] });
    await expect(
      collect(
        new AwsConnector().discover(
          ctx({
            region: REGION,
            endpoint: 'https://evil.example',
            apiUrl: 'https://evil.example/aws',
            host: 'evil.example',
          }),
        ),
      ),
    ).rejects.toThrow(/tenant-writable AWS endpoint/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('does not take a tenant-supplied host even when mixed with a valid region', async () => {
    setAwsCreds();
    const fetchFn = stubAws({
      instances: [['i-aaa']],
      buckets: [],
    });
    await expect(
      collect(
        new AwsConnector().discover(
          ctx({
            region: REGION,
            customEndpoint: 'https://ec2.us-east-1.amazonaws.com.evil.example',
          }),
        ),
      ),
    ).rejects.toThrow(/tenant-writable AWS endpoint/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('requires a valid AWS region identifier', async () => {
    setAwsCreds();
    await expect(
      collect(new AwsConnector().discover(ctx({ region: 'us-east-1.evil.example' }))),
    ).rejects.toThrow(/region/);
  });

  it('fails when an EC2 listing is truncated at the page cap', async () => {
    setAwsCreds();
    const pages = Array.from({ length: AWS_MAX_PAGES }, (_, p) =>
      Array.from({ length: AWS_PER_PAGE }, (_, i) => `i-${p}-${i}`),
    );
    const fetchFn = stubAws({ instances: pages, buckets: [] });
    await expect(
      collect(
        new AwsConnector().discover(ctx({ region: REGION, resourceTypes: ['ec2_instance'] })),
      ),
    ).rejects.toThrow(/truncated/);
    const ec2Calls = fetchFn.mock.calls.filter(
      ([url, init]) =>
        String(url).includes('ec2.') && String(init?.body ?? '').includes('DescribeInstances'),
    );
    expect(ec2Calls).toHaveLength(AWS_MAX_PAGES);
  });

  it('surfaces API failures so the scheduler records them on the integration', async () => {
    setAwsCreds();
    stubAws({ status: 403 });
    await expect(collect(new AwsConnector().discover(ctx()))).rejects.toThrow(/403/);
  });

  it('rejects an unsupported credential scheme loudly', async () => {
    await expect(
      collect(new AwsConnector().discover(ctx({ region: REGION }, 'vault:aws'))),
    ).rejects.toThrow(/Unsupported credentialRef scheme/);
  });

  it('refuses a non-allowlisted env credentialRef without reading the secret', async () => {
    process.env.DATABASE_URL = 'postgres://should-not-leak';
    await expect(
      collect(new AwsConnector().discover(ctx({ region: REGION }, 'env:DATABASE_URL'))),
    ).rejects.toThrow(/not allowlisted/);
  });
});
