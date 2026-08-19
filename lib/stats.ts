/**
 * Anonymous aggregate stats — the only thing vibecheck ever persists, and it is
 * deliberately un-identifying: three integer counters (total scans, scans that
 * were leaking, secret keys caught). NEVER a URL, host, key, or preview.
 *
 * Backed by Upstash Redis over its REST API (Vercel `KV_REST_API_*` or
 * `UPSTASH_REDIS_REST_*` env vars). If neither is configured the whole feature
 * is dormant — recordScan is a no-op and getStats returns null — so the site
 * works fine before you provision a store.
 */

export interface Stats {
  total: number;
  leaking: number;
  secrets: number;
}

const KEYS = { total: 'vc:total', leaking: 'vc:leaking', secrets: 'vc:secrets' };

const restUrl = () => process.env.KV_REST_API_URL ?? process.env.UPSTASH_REDIS_REST_URL;
const restToken = () => process.env.KV_REST_API_TOKEN ?? process.env.UPSTASH_REDIS_REST_TOKEN;

export function statsEnabled(): boolean {
  return !!(restUrl() && restToken());
}

/** Clamp a client-supplied secret count into a sane range (anti-abuse). */
export function clampSecrets(n: unknown): number {
  const v = typeof n === 'number' ? n : parseInt(String(n ?? 0), 10);
  return Math.max(0, Math.min(50, Number.isFinite(v) ? Math.floor(v) : 0));
}

/** Coerce raw Redis MGET values (strings/null) into a clean Stats object. */
export function computeStats(raw: { total?: unknown; leaking?: unknown; secrets?: unknown }): Stats {
  const n = (v: unknown) => {
    const x = parseInt(String(v ?? '0'), 10);
    return Number.isFinite(x) && x > 0 ? x : 0;
  };
  return { total: n(raw.total), leaking: n(raw.leaking), secrets: n(raw.secrets) };
}

async function rest(path: string, body: unknown): Promise<unknown> {
  const url = restUrl();
  const token = restToken();
  if (!url || !token) return null;
  try {
    const res = await fetch(`${url}${path}`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: JSON.stringify(body),
      // don't let a slow store block anything
      signal: AbortSignal.timeout(4000),
    });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

/** Record one anonymous scan: total++, leaking++ (if it leaked), secrets += count. */
export async function recordScan(input: { leaking: boolean; secrets: number }): Promise<boolean> {
  if (!statsEnabled()) return false;
  const secrets = clampSecrets(input.secrets);
  const commands: unknown[] = [['INCR', KEYS.total]];
  if (input.leaking) commands.push(['INCR', KEYS.leaking]);
  if (secrets > 0) commands.push(['INCRBY', KEYS.secrets, secrets]);
  const out = await rest('/pipeline', commands);
  return out != null;
}

export async function getStats(): Promise<Stats | null> {
  if (!statsEnabled()) return null;
  const out = (await rest('', ['MGET', KEYS.total, KEYS.leaking, KEYS.secrets])) as { result?: unknown[] } | null;
  if (!out) return null;
  const [total, leaking, secrets] = (out.result ?? []) as unknown[];
  return computeStats({ total, leaking, secrets });
}
