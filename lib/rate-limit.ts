/**
 * Per-IP rate limiting for the scan endpoints.
 *
 * Without this, anyone can point vibecheck's endpoints at thousands of sites:
 * every request would originate from our servers and our bill, which makes the
 * tool an anonymising scan proxy and an uncapped cost. A scan is also genuinely
 * expensive — measured, not estimated: ~50 outbound fetches at floor, ~86
 * typical, ~130 worst case (20 script bundles, a second entry-page pass, one
 * source-map fetch per chunk, 10 path probes, 13 fixed + up to 12 bundle-derived
 * route probes). So the cap is low.
 *
 * Deliberately in-memory: no database, no dependency. It is per-FUNCTION and
 * per-instance — each scan route is its own module with its own bucket map — so
 * the effective global cap is unknowable, and no tuning changes that. It is a
 * cost ceiling, not a security control. The SSRF guard is what actually
 * prevents harm; this prevents volume.
 *
 * Trigger to replace: sustained abuse visible in function logs without 429s.
 * Then add one Vercel WAF rate-limit rule on /api/scan/* — counters are
 * per-region, which is much-more-global than this, though still not global.
 *
 * ⚠️ Do NOT "fix" amplification with a target-keyed bucket here. One scan fires
 * 12 concurrent requests for the SAME host, so whichever lands first would eat
 * that host's budget and the other 11 would 429 — turning every honest scan
 * into a partial one. Real per-target throttling needs shared state and one
 * budget per (client, host) SCAN, not per request.
 */

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  retryAfterSeconds: number;
}

const WINDOW_MS = 60_000;
// One full report is 12 inbound calls (11 POSTs plus the Lighthouse GET), so
// this is 5 reports per minute per IP — not the 10 an earlier comment claimed
// from a stale count of 6. Still far more than any human scanning apps back to
// back, and a hard ceiling on scripted abuse. Set too low (it was 12) real users
// hit the wall after two scans, which for a free viral tool is worse than the
// abuse. If it is ever raised, stop at 120 (10 reports/min): higher and it stops
// being a cost ceiling, which is the only job it has.
const MAX_PER_WINDOW = 60;

type Bucket = { count: number; resetAt: number };
const buckets = new Map<string, Bucket>();

/** Best-effort client identity from proxy headers (Vercel sets x-forwarded-for). */
export function clientKey(headers: Headers): string {
  const fwd = headers.get('x-forwarded-for') ?? '';
  const first = fwd.split(',')[0]?.trim();
  return first || headers.get('x-real-ip') || 'unknown';
}

/** Sweep expired buckets so the map can't grow without bound. */
function sweep(now: number): void {
  if (buckets.size < 5000) return;
  for (const [k, b] of buckets) if (b.resetAt <= now) buckets.delete(k);
}

export function checkRateLimit(key: string, now = Date.now()): RateLimitResult {
  sweep(now);
  const bucket = buckets.get(key);
  if (!bucket || bucket.resetAt <= now) {
    buckets.set(key, { count: 1, resetAt: now + WINDOW_MS });
    return { allowed: true, remaining: MAX_PER_WINDOW - 1, retryAfterSeconds: 0 };
  }
  if (bucket.count >= MAX_PER_WINDOW) {
    return { allowed: false, remaining: 0, retryAfterSeconds: Math.ceil((bucket.resetAt - now) / 1000) };
  }
  bucket.count += 1;
  return { allowed: true, remaining: MAX_PER_WINDOW - bucket.count, retryAfterSeconds: 0 };
}

/** Test seam: drop all state. */
export function resetRateLimit(): void {
  buckets.clear();
}

/** A ready-to-return 429, or null when the request may proceed. */
export function rateLimitResponse(headers: Headers): Response | null {
  const { allowed, retryAfterSeconds } = checkRateLimit(clientKey(headers));
  if (allowed) return null;
  return new Response(
    JSON.stringify({ error: `Too many scans — try again in ${retryAfterSeconds}s.` }),
    {
      status: 429,
      headers: { 'content-type': 'application/json', 'retry-after': String(retryAfterSeconds) },
    },
  );
}
