import { randomUUID } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { describe, expect, it, vi, beforeEach } from 'vitest';
import type { ScanContext } from '@ctem/scanner-sdk';
import type { ProbeResult } from './surface.probe';

const resolve4Mock = vi.hoisted(() => vi.fn());
const resolve6Mock = vi.hoisted(() => vi.fn());
const resolveCnameMock = vi.hoisted(() => vi.fn());
const resolveNsMock = vi.hoisted(() => vi.fn());

const netConnectMock = vi.hoisted(() => vi.fn());
const tlsConnectMock = vi.hoisted(() => vi.fn());
const httpRequestMock = vi.hoisted(() => vi.fn());
const httpsRequestMock = vi.hoisted(() => vi.fn());

vi.mock('node:dns/promises', () => ({
  resolve4: resolve4Mock,
  resolve6: resolve6Mock,
  resolveCname: resolveCnameMock,
  resolveNs: resolveNsMock,
}));

vi.mock('node:net', async () => {
  const actual = await vi.importActual<typeof import('node:net')>('node:net');
  return {
    connect: netConnectMock,
    isIP: actual.isIP,
  };
});

vi.mock('node:tls', () => ({
  connect: tlsConnectMock,
}));

vi.mock('node:http', () => ({
  request: httpRequestMock,
}));

vi.mock('node:https', () => ({
  request: httpsRequestMock,
}));

import { AsmScanner } from './asm.scanner';
import { SurfaceProbe } from './surface.probe';

function ctx(overrides: Partial<ScanContext['job']> = {}, checkDeadline: () => boolean = () => true): ScanContext {
  return {
    job: {
      jobId: randomUUID(),
      scanId: randomUUID(),
      orgId: randomUUID(),
      scannerType: 'asm',
      assetId: randomUUID(),
      target: { kind: 'domain', externalKey: 'domain:example.com' },
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

describe('AsmScanner.execute findings + completeness', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    resolve4Mock.mockResolvedValue([]);
    resolve6Mock.mockResolvedValue([]);
    resolveCnameMock.mockResolvedValue([]);
    resolveNsMock.mockResolvedValue([]);
  });

  it('emits open-port, tls-* and missing-header findings with unique externalIds (no dangling CNAME collision)', async () => {
    const mockProbe = {
      probe: vi.fn(async () =>
        ({
          host: 'example.com',
          addresses: ['93.184.216.34'],
          cnames: [],
          danglingCname: true,
          openPorts: [80, 443],
          tls: {
            443: { expiresAt: '2025-01-01T00:00:00.000Z', issuer: 'issuer', selfSigned: true },
          },
          httpRoot: { port: 80, protocol: 'http', usedMethod: 'HEAD' },
          headers: {
            'strict-transport-security': 'max-age=100',
          },
        }) satisfies ProbeResult,
      ),
    };

    const scanner = new AsmScanner(mockProbe as any);
    const outcome = await scanner.execute(ctx({ target: { kind: 'domain', externalKey: 'domain:example.com' } }));

    const ids = outcome.findings.map((f) => f.externalId);
    expect(new Set(ids).size).toBe(ids.length);

    expect(ids).toContain('asm.dangling-cname:example.com');
    expect(ids).toContain('asm.open-port:example.com:80');
    expect(ids).toContain('asm.open-port:example.com:443');
    expect(ids).toContain('asm.tls-self-signed:example.com:443');
    expect(ids).toContain('asm.missing-header:example.com:80:content-security-policy');
    expect(ids).not.toContain('asm.missing-header:example.com:80:strict-transport-security');
  });

  it('deadline mid-port scan causes execute to reject (no partial success/findings; no TLS/HTTP)', async () => {
    resolve4Mock.mockResolvedValue(['93.184.216.34']);
    resolve6Mock.mockResolvedValue([]);
    resolveCnameMock.mockResolvedValue([]);

    netConnectMock.mockImplementation(({ port }: any) => {
      const sock = new EventEmitter() as any;
      sock.destroy = () => sock.emit('close');
      if (port === 80) process.nextTick(() => sock.emit('connect'));
      else process.nextTick(() => sock.emit('error', new Error('refused')));
      return sock;
    });

    let calls = 0;
    const checkDeadline = () => {
      calls += 1;
      // Probe:
      // 1) mustHaveDeadline pre-resolve
      // 2) mustHaveDeadline post-resolve
      // 3) mustHaveDeadline before port 80
      // 4) ctx.checkDeadline inside tcpConnectAny for port 80
      // => 5) mustHaveDeadline before port 443 => throw
      return calls < 5;
    };

    const realProbe = new SurfaceProbe();
    const scanner = new AsmScanner(realProbe);

    await expect(
      scanner.execute(ctx({ target: { kind: 'domain', externalKey: 'domain:example.com' } }, checkDeadline)),
    ).rejects.toThrow(/deadline/i);

    expect(tlsConnectMock).not.toHaveBeenCalled();
    expect(httpRequestMock).not.toHaveBeenCalled();
    expect(httpsRequestMock).not.toHaveBeenCalled();

    const ports = netConnectMock.mock.calls.map((c: any[]) => c[0]?.port).filter(Boolean);
    expect(ports).toContain(80);
    expect(ports).not.toContain(443);
  });

  it('creates tls-expired and tls-expiring findings (deterministic time)', async () => {
    const now = new Date('2026-09-03T00:00:00.000Z');
    vi.useFakeTimers();
    vi.setSystemTime(now);

    const mockProbe = {
      probe: vi.fn(async () =>
        ({
          host: 'example.com',
          addresses: ['93.184.216.34'],
          cnames: [],
          danglingCname: false,
          openPorts: [443, 8443],
          tls: {
            443: { expiresAt: new Date(now.getTime() - 24 * 3_600_000).toISOString(), issuer: 'CN=CA', selfSigned: false },
            8443: { expiresAt: new Date(now.getTime() + 5 * 3_600_000).toISOString(), issuer: 'CN=CA', selfSigned: false },
          },
          httpRoot: null,
          headers: {},
        }) satisfies ProbeResult,
      ),
    };

    const scanner = new AsmScanner(mockProbe as any);
    const outcome = await scanner.execute(ctx({ target: { kind: 'domain', externalKey: 'domain:example.com' } }));

    expect(outcome.findings.map((f) => f.externalId)).toEqual(
      expect.arrayContaining(['asm.tls-expired:example.com:443', 'asm.tls-expiring:example.com:8443']),
    );

    vi.useRealTimers();
  });
});

