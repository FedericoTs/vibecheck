/**
 * Per-IP rate limiting for the scan endpoints.
 *
 * Without this, anyone can point vibecheck's endpoints at thousands of sites:
 * every request would originate from our servers and our bill, which makes the
 * tool an anonymising scan proxy and an uncapped cost. A scan is also genuinely
 * expensive (one scan fans out to ~40 outbound fetches), so the cap is low.
 *
 * Deliberately in-memory: no database, no dependency. On serverless this is
 * per-instance rather than global, so it is a speed bump for casual abuse and a
 * cost ceiling per instance — not a security control. The SSRF guard is what
 * actually prevents harm; this prevents volume.
 */

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  retryAfterSeconds: number;
}

const WINDOW_MS = 60_000;
const MAX_PER_WINDOW = 12; // one full report ≈ 6 endpoint calls, so ~2 scans/min

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
