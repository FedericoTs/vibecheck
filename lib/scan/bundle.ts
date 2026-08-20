import { assertPublicUrl } from './ssrf';
import { safeFetch, UA } from './fetch';

export const MAX_BYTES = 2_000_000;
export const MAX_SCRIPTS = 20;
export const BUNDLE_TIMEOUT_MS = 8000;

/**
 * Bundles most likely to carry the app's config/credentials get fetched first,
 * so a page with dozens of chunks still gets its main bundle scanned.
 */
const PRIORITY = /(main|index|app|entry|client|bundle|vendor|runtime|chunk|_app|layout|page)/i;

/**
 * Last two labels of a host. This is a RANKING heuristic only — it is wrong for
 * multi-part suffixes like .co.uk, and that is fine because nothing about
 * safety depends on it. Never use it as a security check.
 */
function siteOf(host: string): string {
  return host.split('.').slice(-2).join('.');
}

/**
 * Match PRIORITY against the FILENAME, never the whole URL. Tested against the
 * full URL, a host like `myapp.com` contains "app" and `landingpage.io`
 * contains "page", so every chunk scored as priority and the ranking silently
 * did nothing.
 */
function isPriority(u: string): boolean {
  try {
    return PRIORITY.test(new URL(u).pathname.split('/').pop() ?? '');
  } catch {
    return false;
  }
}

/**
 * Every `<script src>` in the page HTML, most-likely-relevant first.
 *
 * Cross-origin hosts are INCLUDED deliberately. Serving chunks from a separate
 * asset host (`assetPrefix`) is common — supabase.com serves all 37 of its
 * scripts from frontend-assets.supabase.com — and a same-origin-only filter
 * made the scanner report "no secrets found ✅" on those sites having read no
 * JavaScript whatsoever. A silent false pass is the worst failure this tool has.
 *
 * Safety does NOT come from this function. These URLs are attacker-controlled
 * in the sense that they come from the TARGET's HTML, so each one is revalidated
 * against the SSRF guard in {@link fetchScript} — otherwise an `assetPrefix` of
 * `http://169.254.169.254/` would turn the scanner into a proxy for cloud
 * metadata.
 */
export function scriptUrls(html: string, pageUrl: URL, limit: number = MAX_SCRIPTS): string[] {
  const urls = new Set<string>();
  for (const m of html.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)) {
    try {
      const u = new URL(m[1], pageUrl);
      const isHttp = u.protocol === 'https:' || u.protocol === 'http:';
      if (isHttp && (u.pathname.endsWith('.js') || u.pathname.endsWith('.mjs'))) urls.add(u.toString());
    } catch {
      /* skip unparseable src */
    }
  }

  // The app's own code must win the cap: same origin first, then the same site
  // (the CDN asset-host case), then anything else the page happens to load.
  const site = siteOf(pageUrl.host);
  const tier = (u: string): number => {
    try {
      const h = new URL(u);
      if (h.origin === pageUrl.origin) return 0;
      return siteOf(h.host) === site ? 1 : 2;
    } catch {
      return 2;
    }
  };

  return [...urls]
    .sort((a, b) => tier(a) - tier(b) || (isPriority(b) ? 1 : 0) - (isPriority(a) ? 1 : 0))
    .slice(0, limit);
}

/**
 * Fetch one script's text, or '' if it cannot be read.
 *
 * The SSRF revalidation lives HERE rather than at the call site, so every path
 * that pulls a URL out of a target's markup is safe by construction. safeFetch
 * revalidates each redirect hop for the same reason — a CDN 302 must not be
 * able to land on a private address.
 */
export async function fetchScript(url: string): Promise<string> {
  try {
    const safe = await assertPublicUrl(url);
    const { response } = await safeFetch(safe, {
      headers: { 'user-agent': UA },
      timeoutMs: BUNDLE_TIMEOUT_MS,
    });
    if (!response.ok) return '';
    return (await response.text()).slice(0, MAX_BYTES);
  } catch {
    return '';
  }
}
