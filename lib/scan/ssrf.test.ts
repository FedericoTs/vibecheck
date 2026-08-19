import { describe, it, expect } from 'vitest';
import { isPrivateIp, isPrivateHostname, assertPublicUrl } from './ssrf';

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
