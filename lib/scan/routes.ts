import type { Grade } from './types';
import { scoreToGrade } from './grade';

/**
 * Unprotected admin / debug / data routes.
 *
 * The bug: an AI-generated app ships `/admin` or `/api/users` with no auth gate,
 * so anyone can open the dashboard or pull the user list.
 *
 * The hard part is precision. Single-page apps return `200` plus the same HTML
 * shell for EVERY path, so "200 means exposed" would flag almost every React
 * app. So each probe is judged against the site's own homepage as a baseline,
 * and only counts as exposed when the response is genuinely distinct, is not an
 * auth gate, and actually looks like admin content or real data.
 *
 * GET-only, read-only — it never posts, mutates, or attempts a login.
 */

export type RouteKind = 'admin' | 'debug' | 'data';

export interface RouteProbe {
  path: string;
  label: string;
  kind: RouteKind;
}

export type RouteVerdict = 'exposed' | 'protected' | 'absent' | 'inconclusive';

export interface RouteFinding {
  path: string;
  label: string;
  kind: RouteKind;
  verdict: RouteVerdict;
  detail?: string;
}

export interface RoutesScanResult {
  host: string;
  findings: RouteFinding[];
  exposed: RouteFinding[];
  grade: Grade;
  score: number;
  summary: string;
}

export const ROUTE_PROBES: RouteProbe[] = [
  { path: '/admin', label: 'Admin dashboard (/admin)', kind: 'admin' },
  { path: '/admin/dashboard', label: 'Admin dashboard (/admin/dashboard)', kind: 'admin' },
  { path: '/administrator', label: 'Admin panel (/administrator)', kind: 'admin' },
  { path: '/api/admin', label: 'Admin API (/api/admin)', kind: 'admin' },
  { path: '/api/users', label: 'User list API (/api/users)', kind: 'data' },
  { path: '/api/customers', label: 'Customer API (/api/customers)', kind: 'data' },
  { path: '/api/orders', label: 'Orders API (/api/orders)', kind: 'data' },
  { path: '/api/debug', label: 'Debug endpoint (/api/debug)', kind: 'debug' },
  { path: '/debug', label: 'Debug page (/debug)', kind: 'debug' },
  { path: '/phpinfo.php', label: 'phpinfo()', kind: 'debug' },
];

// ── pure classification ──────────────────────────────────────────────

/**
 * Collapse markup/whitespace so two renders of the same shell compare equal.
 * The <title> is stripped because that is exactly what legitimately varies
 * per-route in a single-page app while the shell stays identical.
 */
export function fingerprint(body: string): string {
  return body
    .replace(/<title[^>]*>[\s\S]*?<\/title>/gi, '<title/>')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 400);
}

/** Is this response just the site's own app shell (SPA catch-all)? */
export function isSameShell(body: string, baseline: string): boolean {
  if (!baseline) return false;
  const a = fingerprint(body);
  const b = fingerprint(baseline);
  if (a === b) return true;
  // near-identical length + same opening markup = same shell with a different title
  const lenClose = Math.abs(body.length - baseline.length) / Math.max(body.length, baseline.length, 1) < 0.05;
  return lenClose && a.slice(0, 200) === b.slice(0, 200);
}

/** Does the page present an authentication gate? Then it is protected, not exposed. */
export function looksLikeAuthGate(body: string): boolean {
  const s = body.slice(0, 20000).toLowerCase();
  if (/type=["']password["']/.test(s)) return true;
  return /(sign in|log ?in|unauthor|forbidden|not authenticated|please authenticate|access denied|session expired)/.test(s);
}

/**
 * A "soft 404": HTTP 200 carrying a not-found page. Common on Next/Vercel and
 * any SPA with a custom 404, and a trap for naive probing — the response is
 * neither the app shell nor the thing you asked for.
 */
export function looksLikeSoftNotFound(body: string): boolean {
  const s = body.slice(0, 6000).toLowerCase();
  return /(404|page not found|not found|page could not be found|page doesn'?t exist|couldn'?t find that page)/.test(s);
}

/**
 * Positive evidence that a debug endpoint is really serving debug output —
 * required before flagging one, so a soft-404 or marketing page can't be
 * mistaken for an exposed debugger.
 */
export function looksLikeDebugOutput(body: string): boolean {
  const s = body.slice(0, 20000).toLowerCase();
  return (
    /phpinfo\(\)|php version|<h1[^>]*>php/.test(s) ||
    /\b(stack ?trace|traceback \(most recent call last\)|exception in thread)\b/.test(s) ||
    /\b(process\.env|environment variables|env dump|debug ?mode: ?(on|true))\b/.test(s) ||
    /\b(server-status|apache server status|whitelabel error page)\b/.test(s)
  );
}

/** Does the body look like a real admin UI rather than a marketing page? */
export function looksLikeAdminUi(body: string): boolean {
  const s = body.slice(0, 20000).toLowerCase();
  const hits = [
    /\badmin (dashboard|panel|console)\b/,
    /\b(manage|all) users\b/,
    /\bdelete (user|account|record)\b/,
    /\brole\b[\s\S]{0,40}\b(admin|editor|owner)\b/,
    /<table[\s\S]{0,400}\b(email|user|role|status)\b/,
  ].filter((re) => re.test(s)).length;
  return hits >= 1;
}

/** JSON payload that actually carries records (not an error or an empty list). */
export function looksLikeData(contentType: string, body: string): boolean {
  if (!/application\/json/i.test(contentType)) return false;
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return false;
  }
  if (Array.isArray(parsed)) return parsed.length > 0;
  if (parsed && typeof parsed === 'object') {
    const o = parsed as Record<string, unknown>;
    if (o.error || o.message === 'Unauthorized' || o.statusCode === 401) return false;
    // a wrapped collection, e.g. { users: [...] } or { data: [...] }
    return Object.values(o).some((v) => Array.isArray(v) && v.length > 0);
  }
  return false;
}

export interface ProbeResponse {
  status: number;
  contentType: string;
  body: string;
  redirected: boolean;
}

export function classifyRoute(probe: RouteProbe, res: ProbeResponse, baseline: string): RouteFinding {
  const base = { path: probe.path, label: probe.label, kind: probe.kind };

  if (res.status === 404 || res.status === 410) return { ...base, verdict: 'absent' };
  if (res.status === 401 || res.status === 403) return { ...base, verdict: 'protected', detail: 'requires authentication' };
  if (res.redirected || (res.status >= 300 && res.status < 400)) {
    return { ...base, verdict: 'protected', detail: 'redirects (likely to a login)' };
  }
  if (res.status !== 200) return { ...base, verdict: 'absent' };

  if (looksLikeAuthGate(res.body)) return { ...base, verdict: 'protected', detail: 'shows a login/authentication gate' };

  if (probe.kind === 'data') {
    return looksLikeData(res.contentType, res.body)
      ? { ...base, verdict: 'exposed', detail: 'returns records to anonymous visitors' }
      : { ...base, verdict: 'absent' };
  }

  // HTML routes: an SPA serves the same shell everywhere, which proves nothing.
  if (isSameShell(res.body, baseline)) {
    return { ...base, verdict: 'inconclusive', detail: 'app shell — routing/auth happens in the browser' };
  }
  // A 200-status "not found" page means the route isn't really there.
  if (looksLikeSoftNotFound(res.body)) return { ...base, verdict: 'absent' };

  if (probe.kind === 'debug') {
    return looksLikeDebugOutput(res.body)
      ? { ...base, verdict: 'exposed', detail: 'debug output served publicly' }
      : { ...base, verdict: 'inconclusive', detail: 'page exists but no debug output detected' };
  }
  return looksLikeAdminUi(res.body)
    ? { ...base, verdict: 'exposed', detail: 'admin interface rendered without authentication' }
    : { ...base, verdict: 'inconclusive', detail: 'page exists but content is unclear' };
}

export function gradeRoutes(findings: RouteFinding[], host = ''): RoutesScanResult {
  const exposed = findings.filter((f) => f.verdict === 'exposed');
  const score = Math.max(0, 100 - exposed.length * 45);
  return {
    host,
    findings,
    exposed,
    grade: scoreToGrade(score),
    score,
    summary:
      exposed.length === 0
        ? 'No unprotected admin or debug routes found ✅'
        : `${exposed.length} route(s) reachable without logging in ⚠️`,
  };
}
