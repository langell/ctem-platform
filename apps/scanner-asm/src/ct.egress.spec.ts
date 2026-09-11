import { describe, expect, it } from 'vitest';
import {
  CRT_SH_HOST,
  allowlistedCrtShUrl,
  crtShQueryUrl,
  ignoredTenantEnumKeys,
  isCrtShHost,
  nextRelFromLinkHeader,
} from './ct.egress';

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

describe('isCrtShHost', () => {
  it('accepts only the exact host crt.sh', () => {
    expect(isCrtShHost('crt.sh')).toBe(true);
    expect(isCrtShHost('CRT.SH')).toBe(true);
    expect(isCrtShHost('crt.sh.')).toBe(true);
    expect(isCrtShHost('www.crt.sh')).toBe(false);
    expect(isCrtShHost('crt.sh.evil.example')).toBe(false);
    expect(isCrtShHost('evil.example')).toBe(false);
  });
});

describe('crtShQueryUrl', () => {
  it('builds %.apex JSON search on crt.sh only', () => {
    expect(crtShQueryUrl('example.com')).toBe(
      `https://${CRT_SH_HOST}/?q=${encodeURIComponent('%.example.com')}&output=json`,
    );
  });
});

describe('nextRelFromLinkHeader', () => {
  it('reads rel=next and ignores other relations', () => {
    expect(nextRelFromLinkHeader('<https://crt.sh/?id=2>; rel="next"')).toBe('https://crt.sh/?id=2');
    expect(nextRelFromLinkHeader('<https://crt.sh/?id=1>; rel="prev"')).toBeUndefined();
    expect(nextRelFromLinkHeader(null)).toBeUndefined();
  });
});

describe('ignoredTenantEnumKeys', () => {
  it('lists tenant wordlist / port / CT URL keys without executing them', () => {
    expect(
      ignoredTenantEnumKeys({
        ctUrl: 'https://evil.example/ct',
        wordlist: ['www', 'api'],
        ports: [22, 23],
        harmless: true,
      }),
    ).toEqual(['wordlist', 'ports', 'ctUrl']);
  });
});
