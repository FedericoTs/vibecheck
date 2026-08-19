import { assertPublicUrl } from './ssrf';

export const UA = 'vibecheck/0.1 (+https://github.com/FedericoTs/vibecheck)';

/**
 * Fetch a public URL following redirects MANUALLY, re-validating every hop
 * against the SSRF guard so a redirect can't smuggle the request to a private
 * host. Returns the final response and the URL it ended on (so callers can
 * resolve relative assets correctly after a redirect).
 */
export async function safeFetch(
  start: URL,
  opts: { timeoutMs?: number; maxRedirects?: number; headers?: Record<string, string> } = {},
): Promise<{ response: Response; url: URL }> {
  const timeoutMs = opts.timeoutMs ?? 8000;
  const maxRedirects = opts.maxRedirects ?? 4;
  let url = start;
  for (let i = 0; i < maxRedirects; i++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    let response: Response;
    try {
      response = await fetch(url.toString(), {
        method: 'GET',
        redirect: 'manual',
        signal: controller.signal,
        headers: { 'user-agent': UA, ...opts.headers },
      });
    } finally {
      clearTimeout(timer);
    }
    const loc = response.headers.get('location');
    if (response.status >= 300 && response.status < 400 && loc) {
      const next = new URL(loc, url);
      await assertPublicUrl(next.toString()); // throws on a private/loopback hop
      url = next;
      continue;
    }
    return { response, url };
  }
  throw new Error('Too many redirects');
}
