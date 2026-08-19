import type { Grade } from './types';
import { scoreToGrade } from './grade';

/**
 * Exposed-files scan. Probes a short list of well-known sensitive paths and
 * flags the ones actually served. The hard part is false positives: single-page
 * apps return 200 + index.html for ANY path, so "200 = exposed" is wrong. Each
 * probe therefore matches the *shape* of the real file (env pairs, git config
 * markers, SQL dump headers) and rejects the HTML app-shell fallback.
 *
 * GET-only, non-destructive — it only reveals files that are already public.
 */

export type Severity = 'high' | 'medium' | 'low';

export interface PathProbe {
  path: string;
  label: string;
  severity: Severity;
  match: (status: number, contentType: string, body: string) => boolean;
}

export interface PathFinding {
  path: string;
  label: string;
  severity: Severity;
  exposed: boolean;
}

export interface PathsScanResult {
  host: string;
  findings: PathFinding[];
  exposed: PathFinding[];
  grade: Grade;
  score: number;
  summary: string;
}

/** Is this the SPA/app-shell HTML fallback rather than the real file? */
export function isHtmlFallback(contentType: string, body: string): boolean {
  if (/text\/html/i.test(contentType)) return true;
  return /^\s*<(!doctype html|html|head|body)/i.test(body);
}

const envMatch = (s: number, ct: string, b: string) =>
  s === 200 && !isHtmlFallback(ct, b) && /^[A-Z0-9_]+\s*=/m.test(b);

const sqlMatch = (s: number, ct: string, b: string) =>
  s === 200 && !isHtmlFallback(ct, b) && /(create table|insert into|--\s*(mysql|postgres) dump|PGDMP)/i.test(b);

/**
 * A server directory index (Apache/nginx autoindex, python http.server). It
 * lists every file in a directory to anyone. The signatures are specific enough
 * that an SPA's index.html served at the same path won't match — a page titled
 * "Index of our products" is not "Index of /".
 */
export const dirListMatch = (s: number, _ct: string, b: string): boolean =>
  s === 200 &&
  /<title>\s*Index of \/|<h1>\s*Index of \/|Directory listing for \/|<address>\s*Apache[\s\S]{0,80}Server at/i.test(b);

// A single publicly-served secret file is a full breach, so one high finding
// alone drops you to F (steeper than a missing header).
const PENALTY: Record<Severity, number> = { high: 65, medium: 25, low: 10 };

export const SENSITIVE_PATHS: PathProbe[] = [
  { path: '/.env', label: '.env (environment secrets)', severity: 'high', match: envMatch },
  { path: '/.env.local', label: '.env.local (local secrets)', severity: 'high', match: envMatch },
  { path: '/.env.production', label: '.env.production (prod secrets)', severity: 'high', match: envMatch },
  {
    path: '/.git/config',
    label: '.git/config (source repo exposed)',
    severity: 'high',
    match: (s, ct, b) => s === 200 && /\[core\]|\[remote |\[branch /i.test(b),
  },
  {
    path: '/.git/HEAD',
    label: '.git/HEAD (source repo exposed)',
    severity: 'high',
    match: (s, _ct, b) => s === 200 && /^ref:\s+refs\/|^[0-9a-f]{40}\s*$/m.test(b.trim()),
  },
  { path: '/uploads/', label: 'Directory listing (/uploads/)', severity: 'medium', match: dirListMatch },
  { path: '/files/', label: 'Directory listing (/files/)', severity: 'medium', match: dirListMatch },
  { path: '/images/', label: 'Directory listing (/images/)', severity: 'low', match: dirListMatch },
  { path: '/backup.sql', label: 'backup.sql (database dump)', severity: 'high', match: sqlMatch },
  { path: '/dump.sql', label: 'dump.sql (database dump)', severity: 'high', match: sqlMatch },
];

/** Classify one probe's response into a finding. */
export function classifyPath(probe: PathProbe, status: number, contentType: string, body: string): PathFinding {
  return {
    path: probe.path,
    label: probe.label,
    severity: probe.severity,
    exposed: probe.match(status, contentType, body),
  };
}

export function gradePaths(findings: PathFinding[], host = ''): PathsScanResult {
  const exposed = findings.filter((f) => f.exposed);
  const score = Math.max(0, 100 - exposed.reduce((s, f) => s + PENALTY[f.severity], 0));
  return {
    host,
    findings,
    exposed,
    grade: scoreToGrade(score),
    score,
    summary:
      exposed.length === 0
        ? 'No sensitive files are publicly served ✅'
        : `${exposed.length} sensitive file${exposed.length === 1 ? '' : 's'} publicly served`,
  };
}
