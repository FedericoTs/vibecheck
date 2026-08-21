import { describe, it, expect } from 'vitest';
import { isPrivateIp, isPrivateHostname, assertPublicUrl, expandIpv6 } from './ssrf';

describe('isPrivateIp', () => {
  it('flags loopback / private / link-local / CGNAT / mapped', () => {
    for (const ip of ['127.0.0.1', '10.1.2.3', '172.16.0.1', '172.31.255.255', '192.168.0.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '::1', 'fc00::1', 'fd12::1', 'fe80::1', '::ffff:127.0.0.1']) {
      expect(isPrivateIp(ip), ip).toBe(true);
    }
  });
  it('passes real public addresses', () => {
    for (const ip of ['8.8.8.8', '1.1.1.1', '172.15.0.1', '172.32.0.1', '93.184.216.34', '2606:2800:220:1::']) {
      expect(isPrivateIp(ip), ip).toBe(false);
    }
  });
});

describe('isPrivateHostname', () => {
  it('refuses localhost / .local / .internal and private IP literals', () => {
    for (const h of ['localhost', 'db.localhost', 'router.local', 'svc.internal', '127.0.0.1', '192.168.1.1']) {
      expect(isPrivateHostname(h), h).toBe(true);
    }
  });
  it('allows public hostnames and public IP literals', () => {
    expect(isPrivateHostname('example.com')).toBe(false);
    expect(isPrivateHostname('8.8.8.8')).toBe(false);
  });
});

describe('assertPublicUrl', () => {
  const publicLookup = async () => [{ address: '93.184.216.34', family: 4 }];
  const privateLookup = async () => [{ address: '10.0.0.5', family: 4 }];

  it('accepts a public URL (adds https, resolves public)', async () => {
    const u = await assertPublicUrl('example.com', publicLookup);
    expect(u.protocol).toBe('https:');
    expect(u.hostname).toBe('example.com');
  });

  it('rejects empty, non-http, and localhost without resolving', async () => {
    await expect(assertPublicUrl('', publicLookup)).rejects.toThrow(/URL/);
    await expect(assertPublicUrl('ftp://example.com', publicLookup)).rejects.toThrow(/http/);
    await expect(assertPublicUrl('http://localhost:3000', publicLookup)).rejects.toThrow(/not publicly/);
  });

  it('rejects a host that RESOLVES to a private address (DNS-rebinding safe)', async () => {
    await expect(assertPublicUrl('rebind.evil.com', privateLookup)).rejects.toThrow(/private/);
  });

  it('rejects a bare private IP literal, accepts a bare public one', async () => {
    await expect(assertPublicUrl('http://169.254.169.254/latest/meta-data', publicLookup)).rejects.toThrow();
    const u = await assertPublicUrl('http://8.8.8.8', publicLookup);
    expect(u.hostname).toBe('8.8.8.8');
  });
});

/**
 * These go through assertPublicUrl, NOT isPrivateIp, and that is the whole
 * point. The suite already asserted isPrivateIp('::ffff:127.0.0.1') === true —
 * a spelling the WHATWG URL parser never produces, since it rewrites the host
 * to the hex form [::ffff:7f00:1]. So the test exercised a branch no real
 * request could reach, and three bypasses survived 495 green tests. Test the
 * thing the request actually flows through.
 */
describe('SSRF bypasses via bracketed IPv6 literals (post-parse)', () => {
  const lookup = async () => [{ address: '93.184.216.34', family: 4 }];
  const allowed = async (url: string): Promise<boolean> => {
    try {
      await assertPublicUrl(url, lookup);
      return true;
    } catch {
      return false;
    }
  };

  it('refuses loopback, private ranges and CLOUD METADATA however they are spelled', async () => {
    for (const url of [
      'http://[::ffff:127.0.0.1]/', // rewritten to [::ffff:7f00:1]
      'http://[::ffff:7f00:1]/', // the hex form directly
      'http://[::ffff:169.254.169.254]/', // AWS/GCP metadata — what the guard exists for
      'http://[::ffff:a9fe:a9fe]/',
      'http://[::ffff:10.0.0.1]/',
      'http://[::ffff:192.168.1.1]/',
      'http://[::1]/',
      'http://[::127.0.0.1]/', // deprecated v4-compatible
      'http://[2002:7f00:1::]/', // 6to4 wrapping 127.0.0.1
      'http://[64:ff9b::a9fe:a9fe]/', // NAT64 wrapping the metadata IP
      'http://[fe80::1]/',
      'http://[fd00::1]/',
      'http://[fc00::1]/',
    ]) {
      expect(await allowed(url), url).toBe(false);
    }
  });

  it('still allows a genuinely public IPv6 host — this is not a blanket ban', async () => {
    expect(await allowed('http://[2606:4700:4700::1111]/')).toBe(true);
  });

  it('refuses anything colon-shaped it cannot parse, rather than guessing', async () => {
    for (const url of ['http://[::ffff:127.0.0.1.5]/', 'http://[:::1]/', 'http://[12345::1]/']) {
      expect(await allowed(url), url).toBe(false);
    }
  });
});

describe('expandIpv6', () => {
  it('normalises every spelling of the same address to the same numbers', () => {
    const loopback = [0, 0, 0, 0, 0, 0, 0, 1];
    expect(expandIpv6('::1')).toEqual(loopback);
    expect(expandIpv6('[::1]')).toEqual(loopback);
    expect(expandIpv6('0:0:0:0:0:0:0:1')).toEqual(loopback);
    // Dotted-quad and hex spellings of ::ffff:127.0.0.1 must agree.
    expect(expandIpv6('::ffff:127.0.0.1')).toEqual(expandIpv6('::ffff:7f00:1'));
  });

  it('drops a zone index, which is not part of the address', () => {
    expect(expandIpv6('fe80::1%eth0')).toEqual(expandIpv6('fe80::1'));
  });

  it('returns null for things that are not IPv6', () => {
    expect(expandIpv6('127.0.0.1')).toBe(null);
    expect(expandIpv6('1::2::3')).toBe(null); // "::" may appear once
    expect(expandIpv6('12345::1')).toBe(null); // group out of range
    expect(expandIpv6('1:2:3:4:5:6:7')).toBe(null); // too few, uncompressed
  });
});
