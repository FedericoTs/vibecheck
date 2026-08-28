import type { Grade } from './types';
import { scoreToGrade } from './grade';

/**
 * Security-headers scan. Given the response headers of the app's deployed URL,
 * grade the presence of the headers that stop the common browser attacks. This
 * only ever reads PUBLIC response headers — no secrets, no auth.
 */

export type Severity = 'high' | 'medium' | 'low';

export interface HeaderCheck {
  key: string;
  label: string;
  present: boolean;
  severity: Severity;
  note: string;
  fix: string;
  /**
   * The check could not apply — it depends on something that is absent, and the
   * absence is already reported by another row. Shown as "not applicable"
   * rather than a green tick, because a tick next to the row that says the thing
   * is missing reads as the tool contradicting itself.
   */
  notApplicable?: boolean;
}

export interface HeadersScanResult {
  host: string;
  checks: HeaderCheck[];
  missing: HeaderCheck[];
  grade: Grade;
  score: number;
  summary: string;
}

const PENALTY: Record<Severity, number> = { high: 25, medium: 12, low: 5 };

/** Lowercase every header key so lookups are case-insensitive. */
export function lowerHeaders(h: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(h)) out[k.toLowerCase()] = v;
  return out;
}

/**
 * Do the cookies set on this response carry Secure + HttpOnly? Vacuously true
 * when the response sets no cookies at all — there is nothing to protect.
 */
/**
 * Is this CSP actually doing anything? A policy containing 'unsafe-inline' or
 * 'unsafe-eval' for scripts, or script-src *, permits precisely the injection a
 * CSP exists to stop — so reporting it as "present" would hand the user a false
 * sense of security. Style-src unsafe-inline is common and far less serious, so
 * it is deliberately not counted.
 */
export function cspIsMeaningful(csp: string | undefined): boolean {
  const v = (csp ?? '').trim();
  if (!v) return false;
  const scriptDirective =
    v.match(/(?:^|;)\s*script-src(?:-elem)?\s([^;]*)/i)?.[1] ??
    v.match(/(?:^|;)\s*default-src\s([^;]*)/i)?.[1] ??
    '';
  if (!scriptDirective) return false;
  if (/'unsafe-inline'|'unsafe-eval'/i.test(scriptDirective)) return false;
  if (/(^|\s)\*(\s|$)|https?:(\s|$)/i.test(scriptDirective)) return false;
  return true;
}

/**
 * Split a joined Set-Cookie header back into individual cookies.
 *
 * Node joins multiple Set-Cookie headers with ", ", and an Expires attribute
 * contains its own comma ("Expires=Wed, 09 Jun 2027 ..."), so a naive split on
 * "," tears cookies in half. Split only on a comma that is followed by a fresh
 * `name=` pair.
 */
export function splitCookies(setCookie: string): string[] {
  return setCookie
    .split(/,(?=\s*[A-Za-z0-9!#$%&'*+.^_`|~-]+\s*=)/)
    .map((c) => c.trim())
    .filter(Boolean);
}

/**
 * Cookies that plausibly carry a session or auth token, judged by name.
 *
 * HttpOnly only matters for a cookie whose theft means something. Requiring it
 * on every cookie flags things like Next.js's NEXT_LOCALE — a locale preference
 * where the flag is meaningless — and that is not a security finding, it is
 * noise that costs a real app a grade. Found by scanning a real Next.js app
 * with i18n, which is a large share of the apps this tool exists for.
 *
 * Secure is different and stays universal: any cookie sent over http leaks.
 */
const SESSION_COOKIE =
  /(^|[-_.])(sess|sid|auth|token|jwt|access|refresh|login|remember|identity|credential)/i;

export function isSessionCookie(cookie: string): boolean {
  const name = cookie.split('=')[0]?.trim() ?? '';
  // __Host-/__Secure- prefixes are only used for cookies that matter.
  if (/^__(Host|Secure)-/i.test(name)) return true;
  return SESSION_COOKIE.test(name);
}

/**
 * True when nothing here is worth grading down.
 *
 * Every cookie must be Secure. HttpOnly is required only of session-like
 * cookies — report-over-grade wherever a legitimate explanation exists, which
 * is this codebase's standing rule.
 */
export function cookiesLookSafe(setCookie: string | undefined): boolean {
  const raw = (setCookie ?? '').trim();
  if (!raw) return true;
  const cookies = splitCookies(raw);
  if (cookies.length === 0) return true;
  return cookies.every((c) => /;\s*secure(\s*;|\s*$)/i.test(c) && (!isSessionCookie(c) || /httponly/i.test(c)));
}

export function gradeHeaders(rawHeaders: Record<string, string>, host = ''): HeadersScanResult {
  const h = lowerHeaders(rawHeaders);
  const csp = h['content-security-policy'] ?? '';

  const checks: HeaderCheck[] = [
    {
      key: 'content-security-policy',
      label: 'Content-Security-Policy',
      present: csp.trim().length > 0,
      severity: 'high',
      note: 'Controls what scripts can run — the main defence against XSS.',
      fix: "Add a Content-Security-Policy header (start with default-src 'self').",
    },
    {
      key: 'strict-transport-security',
      label: 'Strict-Transport-Security (HSTS)',
      present: (h['strict-transport-security'] ?? '').includes('max-age'),
      severity: 'high',
      note:
        'Forces HTTPS so traffic cannot be downgraded. A domain in the browser HSTS preload list gets the same protection without the header, and that list is compiled into the browser rather than served, so it cannot be verified from outside.',
      fix: 'Add Strict-Transport-Security: max-age=31536000; includeSubDomains. If this domain is already in the browser preload list, you have the protection already and this is tidiness rather than exposure.',
    },
    {
      key: 'x-frame-options',
      label: 'Clickjacking protection',
      present: !!h['x-frame-options'] || /frame-ancestors/i.test(csp),
      severity: 'high',
      note: 'Stops your app being framed inside a malicious page.',
      fix: "Add X-Frame-Options: DENY (or CSP frame-ancestors 'none').",
    },
    {
      key: 'x-content-type-options',
      label: 'X-Content-Type-Options',
      present: (h['x-content-type-options'] ?? '').toLowerCase() === 'nosniff',
      severity: 'medium',
      note: 'Stops the browser MIME-sniffing responses into executable types.',
      fix: 'Add X-Content-Type-Options: nosniff.',
    },
    {
      key: 'referrer-policy',
      label: 'Referrer-Policy',
      present: !!h['referrer-policy'],
      severity: 'low',
      note: 'Limits what URL data leaks to third parties.',
      fix: 'Add Referrer-Policy: strict-origin-when-cross-origin.',
    },
    // inverse check: revealing the stack is a (minor) info leak
    {
      key: 'x-powered-by',
      label: 'Hides server stack',
      present: !h['x-powered-by'],
      severity: 'low',
      note: h['x-powered-by']
        ? `Reveals your stack (${h['x-powered-by']}) to attackers.`
        : 'Does not advertise the server stack.',
      fix: 'Remove the X-Powered-By header.',
    },
    {
      key: 'csp-effective',
      label: 'Content-Security-Policy actually restricts scripts',
      // Only meaningful once a CSP exists, and the row above already fails when
      // there is none — but rendering this as a green tick put "CSP not set" and
      // "CSP actually restricts scripts ✓" next to each other in the same panel,
      // which reads as the tool contradicting itself. Not-applicable is the
      // honest state: it still cannot drag the score, and it no longer claims a
      // protection that is absent.
      present: !h['content-security-policy'] ? true : cspIsMeaningful(h['content-security-policy']),
      notApplicable: !h['content-security-policy'],
      severity: 'medium',
      note: "A CSP containing 'unsafe-inline' or 'unsafe-eval' permits the injection it exists to prevent.",
      fix: "Remove 'unsafe-inline' and 'unsafe-eval' from script-src; use nonces or hashes for any inline script.",
    },
    {
      key: 'cors',
      label: 'CORS not wide open with credentials',
      present: !(
        (h['access-control-allow-origin'] ?? '').trim() === '*' &&
        (h['access-control-allow-credentials'] ?? '').toLowerCase() === 'true'
      ),
      severity: 'high',
      note: 'Allow-Origin:* together with Allow-Credentials lets any site read authenticated responses.',
      fix: 'Echo a specific allowed origin instead of *, or drop Allow-Credentials.',
    },
    {
      key: 'cookie-flags',
      label: 'Cookies marked Secure + HttpOnly',
      present: cookiesLookSafe(h['set-cookie']),
      severity: 'medium',
      note: 'Session cookies without HttpOnly can be stolen by any XSS; without Secure they can leak over http.',
      fix: 'Set your session cookies with Secure; HttpOnly; SameSite=Lax.',
    },
  ];

  const missing = checks.filter((c) => !c.present);
  const score = Math.max(0, 100 - missing.reduce((s, c) => s + PENALTY[c.severity], 0));
  const grade = scoreToGrade(score);

  return {
    host,
    checks,
    missing,
    grade,
    score,
    summary:
      missing.length === 0
        ? 'All the key security headers are set ✅'
        : `${missing.length} security header(s) missing or weak`,
  };
}
