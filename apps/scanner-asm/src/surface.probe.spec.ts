import { EventEmitter } from 'node:events';
import { randomUUID } from 'node:crypto';
import { describe, expect, it, vi, beforeEach } from 'vitest';
import type { ScanContext } from '@ctem/scanner-sdk';

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

import { SurfaceProbe } from './surface.probe';
import { ASM_CT_MAX_PAGES, ASM_CT_MAX_RESPONSE_BYTES, CRT_SH_HOST } from './ct.egress';

function ctx(checkDeadline: () => boolean): ScanContext {
  return {
    job: {
      jobId: randomUUID(),
      scanId: randomUUID(),
      orgId: randomUUID(),
      scannerType: 'asm',
      assetId: randomUUID(),
      target: { kind: 'domain', externalKey: 'example.com' },
      credentialRef: null,
      options: {},
      attempt: 1,
      deadlineAt: new Date(Date.now() + 60_000),
      traceId: 'test',
    },
    workDir: '/tmp',
    checkDeadline,
    log: () => undefined,
  };
}

function makeSocket(): EventEmitter & { destroy: () => void } {
  const s = new EventEmitter() as EventEmitter & { destroy: () => void };
  s.destroy = () => {
    // Close is what our connect promise waits on.
    s.emit('close');
  };
  return s;
}

describe('SurfaceProbe.probe SSRF + completeness bars', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Provide safe defaults so tests that don't stub resolution don't
    // accidentally probe.
    resolve4Mock.mockResolvedValue([]);
    resolve6Mock.mockResolvedValue([]);
    resolveCnameMock.mockResolvedValue([]);
    resolveNsMock.mockResolvedValue([]);
  });

  it('refuses literal IPv4 RFC1918 before any TCP connect', async () => {
    const s = new SurfaceProbe();
    const connectSpy = netConnectMock;
    connectSpy.mockReset();

    await expect(
      s.probe(ctx(() => true), { kind: 'host', externalKey: '10.0.0.1' }),
    ).rejects.toThrow(/refused non-public target IP/i);
    expect(connectSpy).not.toHaveBeenCalled();
  });

  it('refuses mixed DNS (public A + private AAAA) without silently skipping the bad answer', async () => {
    resolve4Mock.mockResolvedValue(['93.184.216.34']);
    resolve6Mock.mockResolvedValue(['fd00::1']);
    resolveCnameMock.mockResolvedValue([]);

    const s = new SurfaceProbe();
    netConnectMock.mockReset();
    await expect(s.probe(ctx(() => true), { kind: 'domain', externalKey: 'example.com' })).rejects.toThrow(
      /refused non-public resolved IP/i,
    );
    expect(netConnectMock).not.toHaveBeenCalled();
  });

  it('refuses literal metadata IP 169.254.169.254 before any TCP connect', async () => {
    resolve4Mock.mockResolvedValue(['169.254.169.254']);
    resolve6Mock.mockResolvedValue([]);
    resolveCnameMock.mockResolvedValue([]);

    const s = new SurfaceProbe();
    netConnectMock.mockReset();
    await expect(
      s.probe(ctx(() => true), { kind: 'domain', externalKey: 'example.com' }),
    ).rejects.toThrow(/refused non-public resolved IP/i);
    expect(netConnectMock).not.toHaveBeenCalled();
  });

  it('refuses IPv4-mapped private IPv6 ::ffff:192.168.1.1', async () => {
    resolve4Mock.mockResolvedValue([]);
    resolve6Mock.mockResolvedValue(['::ffff:192.168.1.1']);
    resolveCnameMock.mockResolvedValue([]);

    const s = new SurfaceProbe();
    netConnectMock.mockReset();
    await expect(s.probe(ctx(() => true), { kind: 'domain', externalKey: 'example.com' })).rejects.toThrow(
      /refused non-public resolved IP/i,
    );
    expect(netConnectMock).not.toHaveBeenCalled();
  });

  it('DNS rebinding prevention: connects to vetted IP, preserves TLS SNI and HTTP Host as original name', async () => {
    const HOST = 'example.com';
    const IP = '93.184.216.34';
    const OPEN_PORT = 443;

    resolve4Mock.mockResolvedValue([IP]);
    resolve6Mock.mockResolvedValue([]);
    resolveCnameMock.mockResolvedValue([]);

    netConnectMock.mockImplementation(({ host, port }: any) => {
      expect(host).toBe(IP);
      const sock = makeSocket();
      if (port === OPEN_PORT) process.nextTick(() => sock.emit('connect'));
      else process.nextTick(() => sock.emit('error', new Error('refused')));
      return sock;
    });

    tlsConnectMock.mockImplementation(({ host, port, servername }: any) => {
      expect(host).toBe(IP);
      expect(port).toBe(OPEN_PORT);
      expect(servername).toBe(HOST);

      const sock = makeSocket();
      (sock as any).getPeerCertificate = () => ({
        valid_to: '2099-12-31T00:00:00.000Z',
        issuer: { CN: 'CA', O: 'Test CA' },
        subject: { CN: 'www.example.com' },
      });
      process.nextTick(() => sock.emit('secureConnect'));
      return sock;
    });

    let httpCalls = 0;
    httpsRequestMock.mockImplementation((options: any, cb: any) => {
      httpCalls += 1;
      expect(options.method).toBe('HEAD');
      expect(options.host).toBe(IP);
      expect(options.port).toBe(OPEN_PORT);
      expect(options.path).toBe('/');
      expect(options.headers.host).toBe(HOST);
      expect(options.servername).toBe(HOST);

      const res = new EventEmitter() as any;
      res.statusCode = 302; // redirect must not trigger GET fallback
      res.headers = {
        'strict-transport-security': 'max-age=100',
        'x-frame-options': 'DENY',
        'x-content-type-options': 'nosniff',
        'content-security-policy': "default-src 'self'",
        'x-xss-protection': '1; mode=block',
        'referrer-policy': 'no-referrer',
        'permissions-policy': 'geolocation=()',
        'cross-origin-resource-policy': 'same-origin',
      };
      res.setEncoding = () => undefined;
      process.nextTick(() => {
        cb(res);
        process.nextTick(() => res.emit('end'));
      });

      const req = new EventEmitter() as any;
      req.setTimeout = () => undefined;
      req.destroy = () => undefined;
      req.end = () => undefined;
      req.on = req.on.bind(req);
      return req;
    });

    const s = new SurfaceProbe();
    const out = await s.probe(ctx(() => true), { kind: 'domain', externalKey: `domain:${HOST}` });

    expect(netConnectMock).toHaveBeenCalled();
    expect(tlsConnectMock).toHaveBeenCalled();
    expect(httpCalls).toBe(1); // exactly one HEAD, no redirect follow
    expect(out.host).toBe(HOST);
    expect(out.openPorts).toContain(OPEN_PORT);
  });

  it('HTTP HEAD rejected => exactly one GET fallback and no further requests', async () => {
    const HOST = 'example.com';
    const IP = '93.184.216.34';
    const OPEN_PORT = 443;

    resolve4Mock.mockResolvedValue([IP]);
    resolve6Mock.mockResolvedValue([]);
    resolveCnameMock.mockResolvedValue([]);

    netConnectMock.mockImplementation(({ port }: any) => {
      const sock = makeSocket();
      if (port === OPEN_PORT) process.nextTick(() => sock.emit('connect'));
      else process.nextTick(() => sock.emit('error', new Error('refused')));
      return sock;
    });

    tlsConnectMock.mockImplementation(() => {
      const sock = makeSocket();
      (sock as any).getPeerCertificate = () => ({
        valid_to: '2099-12-31T00:00:00.000Z',
        issuer: { CN: 'CA' },
        subject: { CN: 'www.example.com' },
      });
      process.nextTick(() => sock.emit('secureConnect'));
      return sock;
    });

    const calls: Array<{ method: string; path: string }> = [];
    httpsRequestMock.mockImplementation((options: any, cb: any) => {
      calls.push({ method: options.method, path: options.path });

      const res = new EventEmitter() as any;
      res.setEncoding = () => undefined;

      if (calls.length === 1) {
        // HEAD rejected => GET fallback.
        res.statusCode = 405;
        res.headers = {};
      } else {
        res.statusCode = 200;
        res.headers = {
          'strict-transport-security': 'max-age=100',
          'x-frame-options': 'DENY',
          'x-content-type-options': 'nosniff',
          'content-security-policy': "default-src 'self'",
          'x-xss-protection': '1; mode=block',
          'referrer-policy': 'no-referrer',
          'permissions-policy': 'geolocation=()',
          'cross-origin-resource-policy': 'same-origin',
        };
      }

      process.nextTick(() => {
        cb(res);
        process.nextTick(() => res.emit('end'));
      });

      const req = new EventEmitter() as any;
      req.setTimeout = () => undefined;
      req.destroy = () => undefined;
      req.end = () => undefined;
      return req;
    });

    const s = new SurfaceProbe();
    const out = await s.probe(ctx(() => true), { kind: 'domain', externalKey: `domain:${HOST}` });

    expect(out.openPorts).toContain(OPEN_PORT);
    expect(calls.map((c) => c.method)).toEqual(['HEAD', 'GET']);
  });

  it('parses TLS cert metadata (issuer, expiry, self-signed) from mocked handshake', async () => {
    const HOST = 'example.com';
    const IP = '93.184.216.34';
    const OPEN_PORT = 443;

    resolve4Mock.mockResolvedValue([IP]);
    resolve6Mock.mockResolvedValue([]);
    resolveCnameMock.mockResolvedValue([]);

    netConnectMock.mockImplementation(({ port }: any) => {
      const sock = makeSocket();
      if (port === OPEN_PORT) process.nextTick(() => sock.emit('connect'));
      else process.nextTick(() => sock.emit('error', new Error('refused')));
      return sock;
    });

    tlsConnectMock.mockImplementation((_options: any) => {
      const sock = makeSocket();
      (sock as any).getPeerCertificate = () => ({
        valid_to: '2000-01-01T00:00:00.000Z',
        issuer: { CN: 'Test CA' },
        subject: { CN: 'Test CA' }, // issuer==subject => self-signed by our heuristic
      });
      process.nextTick(() => sock.emit('secureConnect'));
      return sock;
    });

    httpsRequestMock.mockImplementation((options: any, cb: any) => {
      const res = new EventEmitter() as any;
      res.statusCode = 200;
      res.headers = {};
      res.setEncoding = () => undefined;
      process.nextTick(() => {
        cb(res);
        process.nextTick(() => res.emit('end'));
      });
      const req = new EventEmitter() as any;
      req.setTimeout = () => undefined;
      req.destroy = () => undefined;
      req.end = () => undefined;
      return req;
    });

    const s = new SurfaceProbe();
    const out = await s.probe(ctx(() => true), { kind: 'domain', externalKey: `domain:${HOST}` });

    expect(out.openPorts).toContain(OPEN_PORT);
    expect(out.tls).not.toBeNull();
    expect(out.tls?.[OPEN_PORT]).toEqual({
      expiresAt: '2000-01-01T00:00:00.000Z',
      issuer: 'CN=Test CA',
      selfSigned: true,
    });
  });

  it('tenant-supplied scheme/port/path does not drive probing (fixed common ports only)', async () => {
    const HOST = 'example.com';
    const IP = '93.184.216.34';
    const TENANT_PORT = 9999;

    resolve4Mock.mockResolvedValue([IP]);
    resolve6Mock.mockResolvedValue([]);
    resolveCnameMock.mockResolvedValue([]);

    const expectedCommonPorts = [80, 443, 8000, 8008, 8080, 8888, 3000, 5000, 8443, 9443, 10443];

    const usedPorts = new Set<number>();
    netConnectMock.mockImplementation(({ port }: any) => {
      usedPorts.add(port);
      const sock = makeSocket();
      if (port === 80) process.nextTick(() => sock.emit('connect'));
      else process.nextTick(() => sock.emit('error', new Error('refused')));
      return sock;
    });

    tlsConnectMock.mockImplementation(() => {
      throw new Error('TLS should not be attempted when 443 is closed');
    });
    httpsRequestMock.mockImplementation(() => {
      throw new Error('HTTPS should not be attempted when 443 is closed');
    });

    httpRequestMock.mockImplementation((_options: any, cb: any) => {
      const res = new EventEmitter() as any;
      res.statusCode = 200;
      res.headers = { 'strict-transport-security': 'max-age=100' };
      res.setEncoding = () => undefined;
      process.nextTick(() => {
        cb(res);
        process.nextTick(() => res.emit('end'));
      });
      const req = new EventEmitter() as any;
      req.setTimeout = () => undefined;
      req.destroy = () => undefined;
      req.end = () => undefined;
      return req;
    });

    const s = new SurfaceProbe();
    await s.probe(ctx(() => true), { kind: 'api_endpoint', externalKey: `https://${HOST}:${TENANT_PORT}/v1` });

    for (const port of usedPorts) {
      expect(expectedCommonPorts).toContain(port);
    }
    expect(usedPorts.has(TENANT_PORT)).toBe(false);
  });

  it('connection timeout is a completed closed/filtered observation (probe succeeds with no findings)', async () => {
    const IP = '93.184.216.34';
    resolve4Mock.mockResolvedValue([IP]);
    resolve6Mock.mockResolvedValue([]);
    resolveCnameMock.mockResolvedValue([]);

    // Port 80 never connects; everything else errors quickly.
    netConnectMock.mockImplementation(({ port }: any) => {
      const sock = makeSocket();
      if (port === 80) {
        // Never emit connect/error/close; only the probe timeout resolves it.
      } else {
        process.nextTick(() => sock.emit('error', new Error('refused')));
      }
      return sock;
    });

    const s = new SurfaceProbe();
    const out = await s.probe(ctx(() => true), { kind: 'domain', externalKey: 'example.com' });

    expect(out.openPorts).toEqual([]);
    expect(out.tls).toBeNull();
    expect(Object.keys(out.headers)).toEqual([]);
  });
});

const CRT_SH_IP = '93.184.216.34';

function mockCrtShResolve(ip = CRT_SH_IP): void {
  resolve4Mock.mockImplementation(async (host: string) => (host === CRT_SH_HOST ? [ip] : []));
  resolve6Mock.mockResolvedValue([]);
  resolveCnameMock.mockResolvedValue([]);
}

function mockHttpsJson(body: unknown, headers: Record<string, string> = {}): void {
  mockHttpsBody(typeof body === 'string' ? body : JSON.stringify(body), { statusCode: 200, headers });
}

function mockHttpsBody(
  body: string,
  opts: { statusCode?: number; headers?: Record<string, string>; chunks?: string[] } = {},
): void {
  httpsRequestMock.mockImplementation((options: any, cb: any) => {
    const res = new EventEmitter() as any;
    res.statusCode = opts.statusCode ?? 200;
    res.headers = opts.headers ?? {};
    res.setEncoding = () => undefined;
    process.nextTick(() => {
      cb(res);
      process.nextTick(() => {
        for (const chunk of opts.chunks ?? [body]) res.emit('data', chunk);
        res.emit('end');
      });
    });
    const req = new EventEmitter() as any;
    req.setTimeout = () => undefined;
    req.destroy = () => {
      process.nextTick(() => res.emit('end'));
    };
    req.end = () => undefined;
    return req;
  });
}

describe('SurfaceProbe.enumerate CT/DNS allowlist + completeness', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    resolve4Mock.mockResolvedValue([]);
    resolve6Mock.mockResolvedValue([]);
    resolveCnameMock.mockResolvedValue([]);
    resolveNsMock.mockResolvedValue([]);
  });

  it('refuses a non-crt.sh CT next URL and does not connect to it', async () => {
    mockCrtShResolve();
    mockHttpsJson([{ name_value: 'www.example.com' }], {
      link: '<https://evil.example/ct?q=%25.example.com>; rel="next"',
    });

    const s = new SurfaceProbe();
    await expect(s.enumerate('example.com', ctx(() => true))).rejects.toThrow(/only crt\.sh/i);
    const connectHosts = httpsRequestMock.mock.calls.map((c: any[]) => c[0]?.headers?.host);
    expect(connectHosts.every((h) => h === CRT_SH_HOST)).toBe(true);
    expect(httpsRequestMock.mock.calls.map((c: any[]) => c[0]?.port)).toEqual([443]);
  });

  it('refuses a private resolved IP for crt.sh before any CT HTTPS connect', async () => {
    mockCrtShResolve('10.0.0.1');
    const s = new SurfaceProbe();
    await expect(s.enumerate('example.com', ctx(() => true))).rejects.toThrow(
      /refused non-public resolved IP/i,
    );
    expect(httpsRequestMock).not.toHaveBeenCalled();
  });

  it('fails the job when CT JSON is truncated / incomplete', async () => {
    mockCrtShResolve();
    mockHttpsBody('[{"name_value":"www.example.com"');
    const s = new SurfaceProbe();
    await expect(s.enumerate('example.com', ctx(() => true))).rejects.toThrow(/incomplete scope/i);
  });

  it('fails the job when the CT body hits the size cap', async () => {
    mockCrtShResolve();
    mockHttpsBody('', { chunks: ['x'.repeat(ASM_CT_MAX_RESPONSE_BYTES + 1)] });
    const s = new SurfaceProbe();
    await expect(s.enumerate('example.com', ctx(() => true))).rejects.toThrow(
      /truncated at response size cap/i,
    );
  });

  it('fails the job when CT paging is truncated at the page cap', async () => {
    mockCrtShResolve();
    httpsRequestMock.mockImplementation((_options: any, cb: any) => {
      const res = new EventEmitter() as any;
      res.statusCode = 200;
      res.headers = { link: '<https://crt.sh/?q=%25.example.com&output=json&id=2>; rel="next"' };
      res.setEncoding = () => undefined;
      process.nextTick(() => {
        cb(res);
        process.nextTick(() => {
          res.emit('data', '[]');
          res.emit('end');
        });
      });
      const req = new EventEmitter() as any;
      req.setTimeout = () => undefined;
      req.destroy = () => undefined;
      req.end = () => undefined;
      return req;
    });

    const s = new SurfaceProbe();
    await expect(s.enumerate('example.com', ctx(() => true))).rejects.toThrow(/truncated at page cap/i);
    expect(httpsRequestMock).toHaveBeenCalledTimes(ASM_CT_MAX_PAGES);
  });

  it('drops names that are not under the apex suffix', async () => {
    mockCrtShResolve();
    resolveNsMock.mockResolvedValue(['ns1.example.com', 'ns1.other.net']);
    mockHttpsJson([
      { name_value: 'www.example.com\napi.example.com', common_name: 'example.com' },
      { name_value: 'evil.com' },
      { name_value: 'example.com.evil.net' },
      { name_value: 'notexample.com' },
      { name_value: '*.staging.example.com' },
    ]);

    const s = new SurfaceProbe();
    const names = await s.enumerate('example.com', ctx(() => true));
    expect(names).toEqual(['api.example.com', 'example.com', 'ns1.example.com', 'staging.example.com', 'www.example.com']);
    expect(names).not.toContain('evil.com');
    expect(names).not.toContain('example.com.evil.net');
    expect(names).not.toContain('notexample.com');
  });

  it('refuses an IP-literal apex for enumeration', async () => {
    const s = new SurfaceProbe();
    await expect(s.enumerate('8.8.8.8', ctx(() => true))).rejects.toThrow(/IP-literal apex/i);
    expect(httpsRequestMock).not.toHaveBeenCalled();
  });

  it('ignores tenant CT URL / wordlist options and still queries allowlisted crt.sh', async () => {
    mockCrtShResolve();
    mockHttpsJson([]);
    const s = new SurfaceProbe();
    const jobCtx = ctx(() => true);
    jobCtx.job.options = {
      ctUrl: 'https://evil.example/ct',
      wordlist: ['www', 'mail'],
      ports: [22],
    };
    const names = await s.enumerate('example.com', jobCtx);
    expect(names).toEqual([]);
    expect(httpsRequestMock).toHaveBeenCalledTimes(1);
    const opts = httpsRequestMock.mock.calls[0][0];
    expect(opts.host).toBe(CRT_SH_IP);
    expect(opts.port).toBe(443);
    expect(opts.headers.host).toBe(CRT_SH_HOST);
    expect(opts.servername).toBe(CRT_SH_HOST);
    expect(String(opts.path)).toContain('output=json');
    expect(String(opts.path)).toContain(encodeURIComponent('%.example.com'));
  });

  it('connects to the vetted crt.sh IP with Host/SNI crt.sh on port 443', async () => {
    mockCrtShResolve();
    mockHttpsJson([{ common_name: 'www.example.com' }]);
    const s = new SurfaceProbe();
    const names = await s.enumerate('domain:example.com', ctx(() => true));
    expect(names).toEqual(['www.example.com']);
    const opts = httpsRequestMock.mock.calls[0][0];
    expect(opts.method).toBe('GET');
    expect(opts.host).toBe(CRT_SH_IP);
    expect(opts.port).toBe(443);
    expect(opts.headers.host).toBe(CRT_SH_HOST);
    expect(opts.servername).toBe(CRT_SH_HOST);
  });
});

