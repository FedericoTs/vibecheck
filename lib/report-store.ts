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

import { put, head } from '@vercel/blob';
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

/** Storage is optional: with no Blob token configured, saving is simply off. */
export function savingEnabled(): boolean {
  return Boolean(process.env.BLOB_READ_WRITE_TOKEN);
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

export async function saveReport(saved: SavedReport): Promise<string> {
  const { url } = await put(key(saved.slug), JSON.stringify(saved), {
    access: 'public', // unguessable slug is the control; see rule 3
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
    const meta = await head(key(slug));
    const res = await fetch(meta.url, { cache: 'no-store' });
    if (!res.ok) return null;
    const data = (await res.json()) as SavedReport;
    if (data?.v !== SAVED_VERSION) return null;
    if (data.expiresAt && new Date(data.expiresAt).getTime() < Date.now()) return null;
    return data;
  } catch {
    return null;
  }
}
