import { headers } from 'next/headers';

/**
 * Resolve the canonical base URL from configuration, tolerating an unset OR
 * empty `NEXT_PUBLIC_SITE_URL` (an empty value must fall through, which `??`
 * would not do), and never throwing at build time on a malformed value.
 *
 * `VERCEL_URL` is the protected per-deploy host, so it is only a last resort
 * before localhost — prefer {@link siteBaseUrl}, which reads the real request
 * host first.
 */
export function resolveBaseUrl(): URL {
  const explicit = process.env.NEXT_PUBLIC_SITE_URL?.trim();
  const vercel = process.env.VERCEL_URL?.trim();
  const candidate = explicit || (vercel ? `https://${vercel}` : 'http://localhost:3000');
  try {
    return new URL(candidate);
  } catch {
    return new URL('http://localhost:3000');
  }
}

/**
 * Prefer the PUBLIC host the request actually arrived on (the production alias
 * or custom domain) so canonical / OG / sitemap links never point at Vercel's
 * protected per-deploy URL. Falls back to the env resolver when `headers()` is
 * unavailable (e.g. fully static rendering).
 */
export async function siteBaseUrl(): Promise<URL> {
  try {
    const h = await headers();
    const host = h.get('x-forwarded-host') ?? h.get('host');
    if (host) return new URL(`${h.get('x-forwarded-proto') ?? 'https'}://${host}`);
  } catch {
    /* headers() unavailable — fall through to the env resolver */
  }
  return resolveBaseUrl();
}
