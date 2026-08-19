/**
 * SSRF guard for the server-side URL scans. Any endpoint that fetches a
 * user-supplied URL must refuse to reach private/loopback/link-local addresses,
 * or it becomes a proxy into internal networks and cloud metadata (169.254.169.254).
 *
 * The IP/hostname predicates are pure and unit-tested; assertPublicUrl takes an
 * injected DNS lookup so the resolution path is testable too.
 */

export type LookupFn = (host: string) => Promise<Array<{ address: string; family: number }>>;

/** Private, loopback, link-local, and other non-public IPv4/IPv6 ranges. */
export function isPrivateIp(ip: string): boolean {
  const addr = ip.trim().toLowerCase();

  // IPv6
  if (addr.includes(':')) {
    if (addr === '::1' || addr === '::') return true;
    // IPv4-mapped (::ffff:a.b.c.d) — check the embedded v4
    const mapped = addr.match(/::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped) return isPrivateIp(mapped[1]);
    const head = addr.split(':')[0];
    if (head.startsWith('fc') || head.startsWith('fd')) return true; // unique-local fc00::/7
    if (head.startsWith('fe8') || head.startsWith('fe9') || head.startsWith('fea') || head.startsWith('feb'))
      return true; // link-local fe80::/10
    return false;
  }

  // IPv4
  const parts = addr.split('.').map((n) => parseInt(n, 10));
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return false;
  const [a, b] = parts;
  if (a === 10) return true; // 10.0.0.0/8
  if (a === 127) return true; // loopback
  if (a === 0) return true; // 0.0.0.0/8
  if (a === 169 && b === 254) return true; // link-local + cloud metadata
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
  if (a === 192 && b === 168) return true; // 192.168.0.0/16
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT 100.64.0.0/10
  return false;
}

/** Hostnames we refuse without even resolving them. */
export function isPrivateHostname(host: string): boolean {
  const h = host.trim().toLowerCase().replace(/\.$/, '');
  if (!h) return true;
  if (h === 'localhost' || h.endsWith('.localhost')) return true;
  if (h.endsWith('.local') || h.endsWith('.internal') || h.endsWith('.lan')) return true;
  // bare IP literal? validate it directly.
  if (/^[\d.]+$/.test(h) || h.includes(':')) return isPrivateIp(h.replace(/^\[|\]$/g, ''));
  return false;
}

const defaultLookup: LookupFn = async (host) => {
  const dns = await import('node:dns/promises');
  return dns.lookup(host, { all: true });
};

/**
 * Resolve and validate a user-supplied URL for server-side fetching. Throws with
 * a user-safe message on anything non-public.
 */
export async function assertPublicUrl(raw: string, lookup: LookupFn = defaultLookup): Promise<URL> {
  const input = (raw ?? '').trim();
  if (!input) throw new Error('Enter your app URL');
  // Only assume https:// when there's NO scheme; a non-http scheme (ftp:, file:,
  // gopher:) must be parsed as-is so the protocol check below rejects it.
  const hasScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(input);
  const withProto = hasScheme ? input : `https://${input}`;
  let u: URL;
  try {
    u = new URL(withProto);
  } catch {
    throw new Error('That does not look like a URL');
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new Error('Only http(s) URLs are supported');
  if (isPrivateHostname(u.hostname)) throw new Error('That host is not publicly reachable');

  // Not a bare IP → resolve and reject if any address is private (DNS-rebinding safe).
  if (!/^[\d.]+$/.test(u.hostname) && !u.hostname.includes(':')) {
    let addrs: Array<{ address: string }> = [];
    try {
      addrs = await lookup(u.hostname);
    } catch {
      throw new Error('Could not resolve that host');
    }
    if (addrs.length === 0 || addrs.some((a) => isPrivateIp(a.address))) {
      throw new Error('That host resolves to a private address');
    }
  }
  return u;
}
