import type { Grade } from './types';
import { scoreToGrade } from './grade';

/**
 * "Fundamentals" — the cheap, reliable basics derived from the page HTML we
 * already fetch: HTTPS, mixed content, mobile-readiness, and the SEO essentials
 * (title / description / Open Graph / canonical). Presence checks, not an SEO
 * audit — and they render as a SECONDARY section so they never drag the
 * security headline grade.
 */

export type Severity = 'medium' | 'low';

export interface FundamentalCheck {
  key: string;
  label: string;
  pass: boolean;
  severity: Severity;
  fix: string;
}

export interface FundamentalsResult {
  host: string;
  checks: FundamentalCheck[];
  failed: FundamentalCheck[];
  grade: Grade;
  score: number;
  summary: string;
}

const PENALTY: Record<Severity, number> = { medium: 15, low: 7 };

const has = (re: RegExp, s: string) => re.test(s);

export function analyzeFundamentals(html: string, finalUrl: URL): FundamentalsResult {
  const isHttps = finalUrl.protocol === 'https:';
  // Mixed content only matters on an https page.
  const mixed = isHttps && /(?:src|href)\s*=\s*["']http:\/\//i.test(html);

  const checks: FundamentalCheck[] = [
    { key: 'https', label: 'Served over HTTPS', pass: isHttps, severity: 'medium', fix: 'Serve the site over HTTPS.' },
    { key: 'mixed-content', label: 'No mixed (http) content', pass: !mixed, severity: 'medium', fix: 'Load all scripts/styles/images over https://.' },
    { key: 'viewport', label: 'Mobile viewport', pass: has(/<meta[^>]+name=["']viewport["']/i, html), severity: 'medium', fix: 'Add <meta name="viewport" content="width=device-width, initial-scale=1">.' },
    { key: 'title', label: 'Page title', pass: has(/<title[^>]*>[^<]*\S[^<]*<\/title>/i, html), severity: 'low', fix: 'Add a descriptive <title>.' },
    { key: 'description', label: 'Meta description', pass: has(/<meta[^>]+name=["']description["'][^>]+content=["'][^"']+["']/i, html), severity: 'low', fix: 'Add a <meta name="description">.' },
    { key: 'og', label: 'Open Graph tags', pass: has(/<meta[^>]+property=["']og:(title|image)["']/i, html), severity: 'low', fix: 'Add og:title and og:image for social sharing.' },
    { key: 'canonical', label: 'Canonical link', pass: has(/<link[^>]+rel=["']canonical["']/i, html), severity: 'low', fix: 'Add <link rel="canonical"> to avoid duplicate-content issues.' },
    { key: 'lang', label: 'HTML lang attribute', pass: has(/<html[^>]+lang=/i, html), severity: 'low', fix: 'Add a lang attribute to <html> (e.g. lang="en").' },
  ];

  const failed = checks.filter((c) => !c.pass);
  const score = Math.max(0, 100 - failed.reduce((s, c) => s + PENALTY[c.severity], 0));
  return {
    host: finalUrl.host,
    checks,
    failed,
    grade: scoreToGrade(score),
    score,
    summary: failed.length === 0 ? 'All the basics are in place ✅' : `${failed.length} basic${failed.length === 1 ? '' : 's'} missing`,
  };
}
