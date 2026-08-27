/**
 * Saved reports.
 *
 * vibecheck stored nothing for its whole life, and that was a feature: the
 * privacy promise on /legal is the reason people paste a URL into it. Saving
 * changes that, so it changes only under these rules:
 *
 *   1. NEVER automatic. A report is stored when someone presses a button that
 *      says it will be stored, and not before. A scan on its own still leaves
 *      nothing behind.
 *   2. NEVER credentials. We persist the combined report — grades, checks,
 *      details, and the reproduction commands, which are built to carry no
 *      secret. The Supabase key, the probe URL and the raw scan inputs are not
 *      written and must never be added here.
 *   3. UNGUESSABLE and unlisted. The slug is 160 bits of randomness, the page is
 *      noindex, and nothing enumerates saved reports. Knowing the link is the
 *      only way in.
 *   4. It expires. A security report is true about a moment, and one left up for
 *      a year describes an app that no longer exists.
 *
 * Rule 3 is secrecy by URL, which is real but shallow — a link posted publicly
 * is public. That is exactly why the social share buttons point at the
 * stats-only card instead of at this.
 */

import { put, get } from '@vercel/blob';
import type { Report } from './scan/report';

/** Bumped when the stored shape changes, so an old blob can be rejected cleanly. */
export const SAVED_VERSION = 1;

/** How long a saved report stays meaningful. */
export const RETENTION_DAYS = 90;

export interface SavedReport {
  v: number;
  slug: string;
  /** The scanned site, so the report can name and link to its subject. */
  host: string;
  savedAt: string;
  expiresAt: string;
  grade: Report['overallGrade'];
  verdict: string;
  issueCount: number;
  passed: number;
  total: number;
  /** Which checks could not run, so a partial scan cannot read as a clean one. */
  skipped: string[];
  categories: Report['categories'];
}

/**
 * Find the Blob token, whatever Vercel decided to call it.
 *
 * The default name is BLOB_READ_WRITE_TOKEN, but connecting a store lets you set
 * an environment-variable PREFIX, which produces `<PREFIX>_READ_WRITE_TOKEN`
 * instead. Hardcoding the default name means a store that is correctly created,
 * correctly connected and correctly deployed still reads as "saving is off",
 * with nothing in the logs to say why. So: take the default if it is there, and
 * otherwise accept any single *_READ_WRITE_TOKEN the environment offers.
 */
export function blobToken(env: NodeJS.ProcessEnv = process.env): string | undefined {
  const raw = env.BLOB_READ_WRITE_TOKEN
    ? env.BLOB_READ_WRITE_TOKEN
    : Object.entries(env).find(([k, v]) => k.endsWith('_READ_WRITE_TOKEN') && v)?.[1];
  return raw ? clean(raw) : undefined;
}

/**
 * Dashboard env editors take the value literally, and the snippet people copy
 * from is written as KEY="value" — so a token pasted with its quotes still
 * looks set, still passes every "is it configured" check, and fails only at the
 * API with an opaque error. Strip the wrapping rather than make someone debug
 * an invisible pair of quotes.
 */
function clean(value: string): string {
  // Written without a regex on purpose: this file has now been mangled twice by
  // shell escaping, and a backreference that silently loses its backslash still
  // compiles and still "works" on the happy path.
  const v = value.trim();
  const first = v[0];
  const isQuote = first === '"' || first === "'";
  const wrapped = isQuote && v.length >= 2 && v[v.length - 1] === first;
  return (wrapped ? v.slice(1, -1) : v).trim();
}

/** Storage is optional: with no Blob token configured, saving is simply off. */
export function savingEnabled(): boolean {
  return Boolean(blobToken());
}

/**
 * 160 bits, base32-ish. Long enough that guessing is not a threat model, short
 * enough to paste into Slack without wrapping.
 */
export function newSlug(random: () => Uint8Array): string {
  const alphabet = 'abcdefghijkmnopqrstuvwxyz23456789'; // no l/0/1, easy to read aloud
  const bytes = random();
  let out = '';
  for (const b of bytes) out += alphabet[b % alphabet.length];
  return out;
}

const key = (slug: string) => `reports/${slug}.json`;

/**
 * Strip anything that should never be written down, whatever the caller passed.
 *
 * Defence in depth: the client already sends only the combined report, but this
 * is the last place that decision can be enforced, and a future refactor that
 * starts posting raw scan inputs should fail closed here rather than silently
 * persist someone's project URL.
 */
export function sanitize(report: Report): Report['categories'] {
  return report.categories.map((c) => ({
    key: c.key,
    group: c.group,
    label: c.label,
    grade: c.grade,
    score: c.score,
    summary: c.summary,
    checks: c.checks.map((k) => ({
      label: k.label,
      pass: k.pass,
      detail: k.detail,
      severity: k.severity,
      graded: k.graded,
      evidence: k.evidence,
    })),
  }));
}

export function buildSaved(opts: {
  slug: string;
  host: string;
  report: Report;
  skipped: string[];
  now: Date;
}): SavedReport {
  const expires = new Date(opts.now.getTime() + RETENTION_DAYS * 24 * 60 * 60 * 1000);
  return {
    v: SAVED_VERSION,
    slug: opts.slug,
    host: opts.host,
    savedAt: opts.now.toISOString(),
    expiresAt: expires.toISOString(),
    grade: opts.report.overallGrade,
    verdict: opts.report.verdict,
    issueCount: opts.report.issueCount,
    passed: opts.report.passed,
    total: opts.report.total,
    skipped: opts.skipped,
    categories: sanitize(opts.report),
  };
}

/**
 * Blobs are PRIVATE.
 *
 * Rule 3 said the unguessable slug was the control, and on a public store the
 * stored JSON would also have been fetchable directly from its blob URL. Private
 * is strictly better: the report can only be read by something holding the
 * token, which means our own server, which means the only way to see a report is
 * the page we render for it. The slug still guards that page.
 */
export async function saveReport(saved: SavedReport): Promise<string> {
  const { url } = await put(key(saved.slug), JSON.stringify(saved), {
    token: blobToken(),
    access: 'private',
    contentType: 'application/json',
    addRandomSuffix: false,
    cacheControlMaxAge: 60 * 60,
  });
  return url;
}

/** Returns null for missing, malformed, wrong-version or expired reports. */
export async function loadReport(slug: string): Promise<SavedReport | null> {
  if (!/^[a-z2-9]{16,64}$/.test(slug)) return null;
  try {
    const res = await get(key(slug), { access: 'private', token: blobToken() });
    // 304 carries no body; we never send a conditional request, so treat any
    // bodyless response as a miss rather than trusting a partial read.
    if (!res || res.statusCode !== 200 || !res.stream) return null;
    const text = await new Response(res.stream).text();
    const data = JSON.parse(text) as SavedReport;
    if (data?.v !== SAVED_VERSION) return null;
    if (data.expiresAt && new Date(data.expiresAt).getTime() < Date.now()) return null;
    return data;
  } catch {
    return null;
  }
}
