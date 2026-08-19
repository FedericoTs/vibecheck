import type { Fetchy, SupabaseScanResult, TableFinding, BucketFinding, RpcFinding } from './types';
import { gradeExposure } from './grade';

/**
 * Supabase public-read exposure scanner.
 *
 * The CVE-2025-48757 class: a Supabase table with Row Level Security off (or a
 * permissive policy) is readable by ANY visitor using the `anon` key — and that
 * key already ships in the app's frontend bundle. This scanner is a mirror, not
 * an exploit: it uses the user's OWN anon key to show them exactly what any
 * visitor can already read. It runs entirely client-side, so the key and any row
 * data never leave the browser.
 *
 * The engine takes an injected `fetch` so every part is unit-testable without a
 * live Supabase project.
 */

// ── pure helpers (unit-tested, no network) ───────────────────────────

/** Normalise any Supabase URL/host to { base origin, host }. Throws on garbage. */
export function normalizeSupabaseUrl(input: string): { base: string; host: string } {
  const raw = (input ?? '').trim();
  if (!raw) throw new Error('Enter your Supabase project URL');
  const withProto = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
  let u: URL;
  try {
    u = new URL(withProto);
  } catch {
    throw new Error('That does not look like a URL');
  }
  return { base: u.origin, host: u.host };
}

/** Table names exposed by PostgREST, read from its OpenAPI/Swagger `paths`. */
export function parseTablesFromOpenApi(doc: unknown): string[] {
  const paths = (doc as { paths?: Record<string, unknown> })?.paths;
  if (!paths || typeof paths !== 'object') return [];
  const out: string[] = [];
  for (const key of Object.keys(paths)) {
    const m = key.match(/^\/([A-Za-z_][A-Za-z0-9_]*)$/); // "/table", not "/" or "/rpc/fn"
    if (m && m[1] !== 'rpc') out.push(m[1]);
  }
  return [...new Set(out)].sort();
}

/** Total row count from a PostgREST `content-range: 0-0/N` (or `* /N`) header. */
export function parseCountHeader(contentRange: string | null): number | null {
  if (!contentRange) return null;
  const m = contentRange.match(/\/(\d+)\s*$/);
  return m ? parseInt(m[1], 10) : null;
}

/** Exposure verdict: the anon role actually returned at least one row. */
export function isExposed(status: number, body: unknown): boolean {
  return status === 200 && Array.isArray(body) && body.length >= 1;
}

/**
 * RPC endpoints PostgREST publishes, from the same OpenAPI doc used for tables.
 * We only LIST them — vibecheck never calls an unknown database function, since
 * executing one could mutate or delete data.
 */
export function parseRpcFromOpenApi(doc: unknown): string[] {
  const paths = (doc as { paths?: Record<string, unknown> })?.paths;
  if (!paths || typeof paths !== 'object') return [];
  const out: string[] = [];
  for (const key of Object.keys(paths)) {
    const m = key.match(/^\/rpc\/([A-Za-z_][A-Za-z0-9_]*)$/);
    if (m) out.push(m[1]);
  }
  return [...new Set(out)].sort();
}

/** Interpret a storage bucket-list response. Anon should NOT be able to enumerate buckets. */
export function classifyBuckets(status: number, body: unknown): BucketFinding {
  if (status !== 200 || !Array.isArray(body)) return { enumerable: false, publicBuckets: [], checked: true };
  const publicBuckets = body
    .filter((b): b is { name?: string; public?: boolean } => !!b && typeof b === 'object')
    .filter((b) => b.public === true)
    .map((b) => String(b.name ?? 'unnamed'));
  return { enumerable: true, publicBuckets, checked: true };
}

// ── network helpers ──────────────────────────────────────────────────

function anonHeaders(anonKey: string): Record<string, string> {
  return { apikey: anonKey, Authorization: `Bearer ${anonKey}` };
}

async function mapLimit<T, R>(items: T[], limit: number, fn: (t: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let i = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (i < items.length) {
      const idx = i++;
      out[idx] = await fn(items[idx]);
    }
  });
  await Promise.all(workers);
  return out;
}

/** Probe one table for anon readability. Never throws — errors become findings. */
export async function probeTable(
  fetchy: Fetchy,
  base: string,
  anonKey: string,
  table: string,
): Promise<TableFinding> {
  const url = `${base}/rest/v1/${encodeURIComponent(table)}?select=*&limit=1`;
  try {
    const res = await fetchy(url, {
      headers: { ...anonHeaders(anonKey), Prefer: 'count=exact' },
    });
    let body: unknown = null;
    try {
      body = await res.json();
    } catch {
      /* non-JSON (blocked) */
    }
    const exposed = isExposed(res.status, body);
    return {
      table,
      exposed,
      rowsVisible: exposed ? parseCountHeader(res.headers.get('content-range')) : 0,
    };
  } catch (e) {
    return { table, exposed: false, rowsVisible: null, error: (e as Error).message };
  }
}

// ── the scan ─────────────────────────────────────────────────────────

export interface ScanOpts {
  url: string;
  anonKey: string;
  fetch?: Fetchy;
  concurrency?: number;
}

export async function scanSupabase(opts: ScanOpts): Promise<SupabaseScanResult> {
  const fetchy = opts.fetch ?? (globalThis.fetch as Fetchy);
  const anonKey = (opts.anonKey ?? '').trim();
  let base = '';
  let host = '';
  try {
    ({ base, host } = normalizeSupabaseUrl(opts.url));
  } catch (e) {
    return blank(host, (e as Error).message);
  }
  if (!anonKey) return blank(host, 'Paste your project anon (public) key');

  // 1) discover tables via the PostgREST OpenAPI root
  let tables: string[] = [];
  let rpc: RpcFinding = { exposed: [], checked: false };
  try {
    const res = await fetchy(`${base}/rest/v1/`, {
      headers: { ...anonHeaders(anonKey), Accept: 'application/openapi+json' },
    });
    if (!res.ok) {
      return blank(
        host,
        res.status === 401
          ? 'The project rejected its public key, so the database could not be checked. That often means the key was rotated (your deployed bundle is stale) or the API is restricted — either way nothing here is a finding.'
          : `Could not reach the project (HTTP ${res.status})`,
      );
    }
    const doc = await res.json();
    tables = parseTablesFromOpenApi(doc);
    rpc = { exposed: parseRpcFromOpenApi(doc), checked: true };
  } catch {
    return blank(
      host,
      'Could not reach the project from the browser — check the URL, or the project blocks cross-origin scans',
    );
  }

  // 2) probe each table for anon readability
  const findings = await mapLimit(tables, opts.concurrency ?? 6, (t) =>
    probeTable(fetchy, base, anonKey, t),
  );
  const exposed = findings.filter((f) => f.exposed);

  // 3) can anonymous visitors enumerate the storage buckets? (read-only)
  let buckets: BucketFinding = { enumerable: false, publicBuckets: [], checked: false };
  try {
    const res = await fetchy(`${base}/storage/v1/bucket`, { headers: anonHeaders(anonKey) });
    let body: unknown = null;
    try {
      body = await res.json();
    } catch {
      /* non-JSON */
    }
    buckets = classifyBuckets(res.status, body);
  } catch {
    /* storage unreachable — leave unchecked */
  }

  // Bucket enumeration is a real exposure; fold it into the grade.
  const extra = (buckets.enumerable ? 1 : 0) + buckets.publicBuckets.length;
  const grade = gradeExposure(exposed.length + extra, tables.length + (buckets.checked ? 1 : 0));

  return {
    ok: true,
    host,
    tablesFound: tables.length,
    findings,
    exposedCount: exposed.length,
    buckets,
    rpc,
    grade: grade.grade,
    summary:
      exposed.length === 0 && extra === 0
        ? `${tables.length} table(s) checked — none readable by anonymous visitors ✅`
        : exposed.length > 0
          ? `${exposed.length} of ${tables.length} table(s) are readable by anyone with your public key ⚠️`
          : 'Your storage buckets are exposed to anonymous visitors ⚠️',
  };
}

function blank(host: string, error: string): SupabaseScanResult {
  return {
    ok: false,
    host,
    tablesFound: 0,
    findings: [],
    exposedCount: 0,
    grade: 'C',
    summary: error,
    error,
  };
}
