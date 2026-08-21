/**
 * Dependency / supply-chain analysis for the repo scan.
 *
 * Vibe-coded apps pull enormous dependency trees their authors never chose
 * deliberately, and 2026 turned that into the dominant attack surface: axios
 * (~100M weekly downloads) turned into a RAT by a compromised maintainer, the
 * self-replicating Shai-Hulud worm, North Korea republishing a whole framework's
 * npm scope. We read the repo's lockfile, resolve exact versions, and ask
 * OSV.dev (free, keyless, no rate limit) which of them carry a known
 * vulnerability or are outright malicious.
 *
 * The parsers and classifiers here are pure and unit-tested; the OSV network
 * call lives in the route.
 */

export type Ecosystem = 'npm' | 'PyPI' | 'Go';

export interface Dep {
  name: string;
  version: string;
  ecosystem: Ecosystem;
}

// ── manifest parsers ─────────────────────────────────────────────────

/** Exact versions from a package-lock.json (v2/v3 `packages`, or v1 `dependencies`). */
export function parseNpmLock(content: string): Dep[] {
  let json: unknown;
  try {
    json = JSON.parse(content);
  } catch {
    return [];
  }
  const out = new Map<string, Dep>();
  const j = json as { packages?: Record<string, { version?: string }>; dependencies?: Record<string, unknown> };

  if (j.packages && typeof j.packages === 'object') {
    for (const [key, val] of Object.entries(j.packages)) {
      if (!key || !val?.version) continue; // "" is the project root
      const name = key.split('node_modules/').pop();
      if (!name) continue;
      out.set(`${name}@${val.version}`, { name, version: val.version, ecosystem: 'npm' });
    }
  }
  if (out.size === 0 && j.dependencies && typeof j.dependencies === 'object') {
    const walk = (deps: Record<string, unknown>) => {
      for (const [name, raw] of Object.entries(deps)) {
        const v = raw as { version?: string; dependencies?: Record<string, unknown> };
        if (v?.version) out.set(`${name}@${v.version}`, { name, version: v.version, ecosystem: 'npm' });
        if (v?.dependencies) walk(v.dependencies);
      }
    };
    walk(j.dependencies as Record<string, unknown>);
  }
  return [...out.values()];
}

/** Extract a concrete version from a semver RANGE (^1.2.3 -> 1.2.3); skip *, latest, git, workspace. */
export function cleanVersion(range: string): string | null {
  const m = String(range).match(/(\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?)/);
  return m ? m[1] : null;
}

/** Declared deps from package.json — a fallback when no lockfile is present (less exact). */
export function parsePackageJson(content: string): Dep[] {
  let json: unknown;
  try {
    json = JSON.parse(content);
  } catch {
    return [];
  }
  const j = json as Record<string, Record<string, string> | undefined>;
  const out = new Map<string, Dep>();
  for (const field of ['dependencies', 'devDependencies']) {
    const deps = j[field];
    if (!deps || typeof deps !== 'object') continue;
    for (const [name, range] of Object.entries(deps)) {
      const version = cleanVersion(range);
      if (version) out.set(`${name}@${version}`, { name, version, ecosystem: 'npm' });
    }
  }
  return [...out.values()];
}

/** Pinned Python deps (only `pkg==1.2.3`, which is the only form we can query exactly). */
export function parseRequirementsTxt(content: string): Dep[] {
  const out: Dep[] = [];
  for (const line of content.split('\n')) {
    const l = line.trim();
    if (!l || l.startsWith('#') || l.startsWith('-')) continue;
    const m = l.match(/^([A-Za-z0-9._-]+)\s*==\s*([0-9][0-9A-Za-z.]*)/);
    if (m) out.push({ name: m[1], version: m[2], ecosystem: 'PyPI' });
  }
  return out;
}

// ── OSV query ────────────────────────────────────────────────────────

/** Body for POST https://api.osv.dev/v1/querybatch */
export function osvBatchBody(deps: Dep[]): { queries: Array<{ package: { name: string; ecosystem: Ecosystem }; version: string }> } {
  return { queries: deps.map((d) => ({ package: { name: d.name, ecosystem: d.ecosystem }, version: d.version })) };
}

/** Map a /querybatch response back to the deps that have advisories. */
export function parseOsvBatch(deps: Dep[], results: Array<{ vulns?: Array<{ id: string }> }> | undefined): Array<{ dep: Dep; ids: string[] }> {
  const out: Array<{ dep: Dep; ids: string[] }> = [];
  const rs = results ?? [];
  for (let i = 0; i < deps.length; i++) {
    const ids = (rs[i]?.vulns ?? []).map((v) => v.id).filter(Boolean);
    if (ids.length) out.push({ dep: deps[i], ids: [...new Set(ids)] });
  }
  return out;
}

export interface OsvVuln {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  severity?: Array<{ type?: string; score?: string }>;
  database_specific?: { severity?: string; malicious?: boolean };
}

export type DepSeverity = 'critical' | 'high' | 'medium';

/** Highest CVSS base score across the severity array, if any. */
export function cvssScore(severity: OsvVuln['severity']): number | null {
  if (!Array.isArray(severity)) return null;
  let best: number | null = null;
  for (const s of severity) {
    const m = String(s?.score ?? '').match(/(\d+(?:\.\d+)?)\/?$|^(\d+(?:\.\d+)?)$/);
    const n = m ? parseFloat(m[1] ?? m[2]) : NaN;
    if (Number.isFinite(n)) best = best == null ? n : Math.max(best, n);
  }
  return best;
}

/**
 * Malicious-package advisory? OSV publishes these as MAL-… or marks them.
 *
 * "MALICIOUS" is the single most damaging word this tool can print about
 * someone's dependency, so it has to be earned. The previous test searched
 * `details` as well as `summary`, and ordinary advisory prose says things like
 * "a malicious user could…" — which branded a perfectly healthy postcss as
 * malicious purely for describing an XSS.
 *
 * The lexical test is kept but restricted to `summary` and anchored to the way
 * malware advisories are actually titled. Deleting it entirely was tempting and
 * wrong: the most famous npm supply-chain compromises predate the MAL- id
 * scheme (eslint-scope is GHSA-hxxf-q3w9-4xgw, ua-parser-js is
 * GHSA-pjwm-rvh2-c87w), so an id-only test would miss them.
 *
 * Validated against real advisories: postcss XSS → clean, postcss ReDoS →
 * clean, eslint-scope → flagged, ua-parser-js → flagged.
 */
export function isMalware(v: OsvVuln): boolean {
  if (/^MAL-/i.test(v.id)) return true;
  if (v.aliases?.some((a) => /^MAL-/i.test(a))) return true;
  if (v.database_specific?.malicious === true) return true;
  return /^malicious\b|\bmalicious (code|package)\b|\bembedded malware\b|\bbackdoor(ed)?\b/i.test(v.summary ?? '');
}

export function classifyVuln(v: OsvVuln): { id: string; summary: string; severity: DepSeverity; malware: boolean } {
  const malware = isMalware(v);
  const dbSev = String(v.database_specific?.severity ?? '').toUpperCase();
  const cvss = cvssScore(v.severity);
  let severity: DepSeverity = 'medium';
  if (malware || dbSev === 'CRITICAL' || (cvss != null && cvss >= 9)) severity = 'critical';
  else if (dbSev === 'HIGH' || (cvss != null && cvss >= 7)) severity = 'high';
  return { id: v.id, summary: v.summary || v.id, severity, malware };
}
