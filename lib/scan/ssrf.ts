/**
 * SSRF guard for the server-side URL scans. Any endpoint that fetches a
 * user-supplied URL must refuse to reach private/loopback/link-local addresses,
 * or it becomes a proxy into internal networks and cloud metadata (169.254.169.254).
 *
 * The IP/hostname predicates are pure and unit-tested; assertPublicUrl takes an
 * injected DNS lookup so the resolution path is testable too.
 */

export type LookupFn = (host: string) => Promise<Array<{ address: string; family: number }>>;

/**
 * Expand an IPv6 literal to its eight 16-bit groups, or null if it is not one.
 *
 * WHY THIS EXISTS RATHER THAN STRING MATCHING
 * -------------------------------------------
 * The previous version matched `::ffff:` followed by a DOTTED QUAD. That form
 * never survives URL parsing: `new URL('http://[::ffff:127.0.0.1]/')` rewrites
 * the host to `[::ffff:7f00:1]`, the hex serialisation of the same address. The
 * regex could not match it, and `addr.split(':')[0]` on a leading-`::` address
 * is the empty string, so the unique-local and link-local prefix checks could
 * not fire either. The result was that loopback, private ranges, AND the cloud
 * metadata endpoint were all reachable through a bracketed literal — in a guard
 * whose own doc comment promises to refuse exactly those.
 *
 * One address has many spellings; comparing spellings is the bug. This
 * normalises to numbers once, and every check below is then arithmetic.
 */
export function expandIpv6(raw: string): number[] | null {
  // Strip brackets and any zone index (%eth0), which is not part of the address.
  let addr = raw.trim().toLowerCase().replace(/^\[|\]$/g, '').split('%')[0];
  if (!addr.includes(':')) return null;

  // A trailing dotted quad (::ffff:127.0.0.1) is two more 16-bit groups.
  const dotted = addr.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
  if (dotted) {
    const octets = dotted[1].split('.').map((n) => parseInt(n, 10));
    if (octets.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return null;
    const hex = [(octets[0] << 8) | octets[1], (octets[2] << 8) | octets[3]]
      .map((g) => g.toString(16))
      .join(':');
    addr = addr.slice(0, dotted.index) + hex;
  }

  const halves = addr.split('::');
  if (halves.length > 2) return null; // "::" may appear at most once
  const parse = (part: string): number[] | null => {
    if (part === '') return [];
    const out: number[] = [];
    for (const g of part.split(':')) {
      if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
      out.push(parseInt(g, 16));
    }
    return out;
  };
  const head = parse(halves[0]);
  const tail = halves.length === 2 ? parse(halves[1]) : [];
  if (!head || !tail) return null;

  if (halves.length === 2) {
    const fill = 8 - head.length - tail.length;
    if (fill < 1) return null;
    return [...head, ...Array(fill).fill(0), ...tail];
  }
  return head.length === 8 ? head : null;
}

/** Private, loopback, link-local, and other non-public IPv4/IPv6 ranges. */
export function isPrivateIp(ip: string): boolean {
  const addr = ip.trim().toLowerCase();

  // IPv6
  if (addr.includes(':')) {
    const g = expandIpv6(addr);
    // Unparseable as IPv6 but contains a colon: refuse rather than guess. This
    // guard's job is to say no when it does not understand something.
    if (!g) return true;

    const v4 = (hi: number, lo: number) => `${hi >> 8}.${hi & 0xff}.${lo >> 8}.${lo & 0xff}`;
    const allZero = (upTo: number) => g.slice(0, upTo).every((x) => x === 0);

    if (allZero(7) && (g[7] === 1 || g[7] === 0)) return true; // ::1 loopback, :: unspecified
    if (allZero(5) && g[5] === 0xffff) return isPrivateIp(v4(g[6], g[7])); // ::ffff:0:0/96 v4-mapped
    if (allZero(6)) return isPrivateIp(v4(g[6], g[7])); // ::a.b.c.d deprecated v4-compatible
    if ((g[0] & 0xfe00) === 0xfc00) return true; // fc00::/7 unique-local
    if ((g[0] & 0xffc0) === 0xfe80) return true; // fe80::/10 link-local
    if (g[0] === 0x2002) return isPrivateIp(v4(g[1], g[2])); // 2002::/16 6to4
    if (g[0] === 0x0064 && g[1] === 0xff9b) return isPrivateIp(v4(g[6], g[7])); // 64:ff9b::/96 NAT64
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

  // Not a bare IP → resolve and reject if any address is private.
  //
  // NB this is NOT DNS-rebinding safe, whatever this comment used to claim. We
  // resolve here and the HTTP client resolves again when it connects, so a
  // hostname with a short TTL can answer public now and private a moment later.
  // Closing it needs the connection pinned to the address we checked, which is
  // a real change to every fetch path. Recorded honestly rather than asserted
  // away — a guard that overstates itself is how the IPv6 hole survived.
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
