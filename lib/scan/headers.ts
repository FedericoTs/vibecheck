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
export function cookiesLookSafe(setCookie: string | undefined): boolean {
  const raw = (setCookie ?? '').trim();
  if (!raw) return true;
  return /httponly/i.test(raw) && /secure/i.test(raw);
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
      note: 'Forces HTTPS so traffic cannot be downgraded.',
      fix: 'Add Strict-Transport-Security: max-age=31536000; includeSubDomains.',
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
