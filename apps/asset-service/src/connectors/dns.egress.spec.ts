import { describe, expect, it } from 'vitest';
import {
  CRT_SH_HOST,
  EXTRA_HOST_KEY_RE,
  TENANT_DNS_DIAL_KEYS,
  allowlistedCrtShUrl,
  crtShQueryUrl,
  isCrtShHost,
  isPublicAddress,
  namesFromCrtShBody,
  nextRelFromLinkHeader,
  normalizeApexFqdn,
  normalizeDiscoveredName,
  refuseTenantDnsDial,
} from './dns.egress';

describe('allowlistedCrtShUrl', () => {
  it('accepts exact host crt.sh over https/443', () => {
    expect(allowlistedCrtShUrl('https://crt.sh/?q=%25.example.com&output=json')).toBe(
      'https://crt.sh/?q=%25.example.com&output=json',
    );
    expect(allowlistedCrtShUrl('https://CRT.SH/?output=json')).toBe('https://crt.sh/?output=json');
  });

  it('refuses a non-crt.sh CT URL', () => {
    expect(() => allowlistedCrtShUrl('https://evil.example/ct?q=%25.example.com')).toThrow(
      /only crt\.sh/,
    );
    expect(() => allowlistedCrtShUrl('https://crt.sh.evil.example/?q=%25.x&output=json')).toThrow(
      /only crt\.sh/,
    );
    expect(() => allowlistedCrtShUrl('https://www.crt.sh/?q=%25.x&output=json')).toThrow(/only crt\.sh/);
    expect(() => allowlistedCrtShUrl('https://crtsh.com/?q=%25.x&output=json')).toThrow(/only crt\.sh/);
  });

  it('refuses http, userinfo, and non-default ports', () => {
    expect(() => allowlistedCrtShUrl('http://crt.sh/?q=%25.x&output=json')).toThrow(/non-https/);
    expect(() => allowlistedCrtShUrl('https://user:pass@crt.sh/?q=%25.x')).toThrow(/userinfo/);
    expect(() => allowlistedCrtShUrl('https://crt.sh:8443/?q=%25.x&output=json')).toThrow(/port/);
  });
});

describe('isCrtShHost / crtShQueryUrl / nextRelFromLinkHeader', () => {
  it('accepts only the exact host crt.sh', () => {
    expect(isCrtShHost('crt.sh')).toBe(true);
    expect(isCrtShHost('CRT.SH')).toBe(true);
    expect(isCrtShHost('crt.sh.')).toBe(true);
    expect(isCrtShHost('www.crt.sh')).toBe(false);
    expect(isCrtShHost('crt.sh.evil.example')).toBe(false);
  });

  it('builds %.apex JSON search on crt.sh only', () => {
    expect(crtShQueryUrl('example.com')).toBe(
      `https://${CRT_SH_HOST}/?q=${encodeURIComponent('%.example.com')}&output=json`,
    );
  });

  it('reads rel=next and ignores other relations', () => {
    expect(nextRelFromLinkHeader('<https://crt.sh/?id=2>; rel="next"')).toBe('https://crt.sh/?id=2');
    expect(nextRelFromLinkHeader('<https://crt.sh/?id=1>; rel="prev"')).toBeUndefined();
    expect(nextRelFromLinkHeader(null)).toBeUndefined();
  });
});

describe('refuseTenantDnsDial', () => {
  it('allows apex / apexes only', () => {
    expect(() => refuseTenantDnsDial({ apexes: ['example.com'] })).not.toThrow();
    expect(() => refuseTenantDnsDial({ apex: 'example.com' })).not.toThrow();
  });

  it('refuses DNS-server / DoH / CT URL / wordlist keys', () => {
    const forbidden: Array<[string, unknown]> = [
      ['nameserver', '10.0.0.1'],
      ['nameservers', ['ns1.evil.example']],
      ['dnsServer', 'https://dns.google/dns-query'],
      ['dnsServers', ['1.1.1.1']],
      ['resolver', '8.8.8.8'],
      ['resolvers', ['8.8.8.8']],
      ['doh', 'https://cloudflare-dns.com/dns-query'],
      ['dohUrl', 'https://dns.google/dns-query'],
      ['baseUrl', 'https://evil.example/dns'],
      ['endpoint', 'https://evil.example/api'],
      ['host', 'dns.evil.example'],
      ['apiUrl', 'https://crt.sh.evil.example/'],
      ['axfr', true],
      ['wordlist', ['www', 'mail']],
      ['ctUrl', 'https://evil.example/ct'],
      ['crtshUrl', 'https://crtsh.com/'],
    ];
    for (const [key, value] of forbidden) {
      expect(TENANT_DNS_DIAL_KEYS).toContain(key);
      expect(() => refuseTenantDnsDial({ apexes: ['example.com'], [key]: value })).toThrow(
        /tenant-writable DNS endpoint/,
      );
    }
  });

  it('refuses EXTRA_*_HOST_KEYS', () => {
    expect(EXTRA_HOST_KEY_RE.test('EXTRA_DNS_HOST_KEYS')).toBe(true);
    expect(() =>
      refuseTenantDnsDial({ apexes: ['example.com'], EXTRA_DNS_HOST_KEYS: ['evil.example'] }),
    ).toThrow(/EXTRA_\*_HOST_KEYS/);
  });
});

describe('normalizeApexFqdn / normalizeDiscoveredName', () => {
  it('lowercases, strips a trailing dot, and requires FQDN labels', () => {
    expect(normalizeApexFqdn('Example.COM.')).toBe('example.com');
    expect(() => normalizeApexFqdn('localhost')).toThrow(/FQDN apex labels only/);
    expect(() => normalizeApexFqdn('8.8.8.8')).toThrow(/IP-literal apex/);
    expect(() => normalizeApexFqdn('https://evil.example')).toThrow(/FQDN apex labels only/);
    expect(() => normalizeApexFqdn('*.example.com')).toThrow(/wildcard/);
  });

  it('drops names outside the apex suffix', () => {
    expect(normalizeDiscoveredName('www.example.com', 'example.com')).toBe('www.example.com');
    expect(normalizeDiscoveredName('*.staging.example.com.', 'example.com')).toBe(
      'staging.example.com',
    );
    expect(normalizeDiscoveredName('evil.com', 'example.com')).toBeNull();
    expect(normalizeDiscoveredName('example.com.evil.net', 'example.com')).toBeNull();
    expect(normalizeDiscoveredName('notexample.com', 'example.com')).toBeNull();
    expect(normalizeDiscoveredName('10.0.0.1', 'example.com')).toBeNull();
  });
});

describe('namesFromCrtShBody / isPublicAddress', () => {
  it('splits name_value / common_name rows', () => {
    expect(
      namesFromCrtShBody(
        JSON.stringify([
          { name_value: 'www.example.com\napi.example.com', common_name: 'example.com' },
        ]),
      ),
    ).toEqual(['www.example.com', 'api.example.com', 'example.com']);
  });

  it('treats RFC1918 / loopback / link-local as non-public', () => {
    expect(isPublicAddress('93.184.216.34')).toBe(true);
    expect(isPublicAddress('10.0.0.1')).toBe(false);
    expect(isPublicAddress('192.168.1.1')).toBe(false);
    expect(isPublicAddress('127.0.0.1')).toBe(false);
    expect(isPublicAddress('169.254.169.254')).toBe(false);
    expect(isPublicAddress('::1')).toBe(false);
    expect(isPublicAddress('fc00::1')).toBe(false);
  });
});
