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

/**
 * pnpm-lock.yaml — exact resolved versions.
 *
 * Without this, a pnpm repo (most modern ones) fell through to package.json's
 * declared RANGES, and every version reported was the range floor — possibly a
 * version the user does not have installed at all.
 *
 * Handles the v9 `packages:`/`snapshots:` keys and the older `/name/version`
 * form, and strips the peer-dependency suffix: `react-dom@18.2.0(react@18.2.0)`
 * must be queried as react-dom@18.2.0, or OSV receives an unresolvable version.
 */
export function parsePnpmLock(content: string): Dep[] {
  const out = new Map<string, Dep>();
  for (const line of content.split('\n')) {
    // Keys sit indented under packages:/snapshots: and end with a colon.
    // The key may be quoted, and scoped names usually are.
    const m = line.match(/^\s{2,}['"]?\/?((?:@[\w.-]+\/)?[\w.-]+)[@/](\d[^:()'"\s]*)(?:\([^)]*\))*['"]?\s*:\s*$/);
    if (!m) continue;
    const [, name, version] = m;
    out.set(`${name}@${version}`, { name, version, ecosystem: 'npm' });
  }
  return [...out.values()];
}

/**
 * yarn.lock — the v1 format (`version "1.2.3"`) and Berry's YAML
 * (`version: 1.2.3`). The header line carries the requested RANGE, so the
 * resolved version is read from the body.
 */
export function parseYarnLock(content: string): Dep[] {
  const out = new Map<string, Dep>();
  let header = '';
  for (const line of content.split('\n')) {
    if (/^\S/.test(line) && line.trim().endsWith(':')) {
      header = line.trim().replace(/:$/, '');
      continue;
    }
    const v = line.match(/^\s+version:?\s+"?([\d][^"\s]*)"?/);
    if (!v || !header) continue;
    // `"react-dom@npm:^18.2.0, react-dom@^18"` -> react-dom
    const first = header.split(',')[0].trim().replace(/^"|"$/g, '');
    const at = first.lastIndexOf('@');
    const name = at > 0 ? first.slice(0, at) : first;
    if (name) out.set(`${name}@${v[1]}`, { name, version: v[1], ecosystem: 'npm' });
  }
  return [...out.values()];
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

/**
 * 'unknown' is a real outcome, not a synonym for medium. Defaulting an
 * unclassified advisory to 'medium' invents a rating the tool never
 * established, and then grades the user on it.
 */
export type DepSeverity = 'critical' | 'high' | 'medium' | 'low' | 'unknown';

/**
 * CVSS base score from an OSV severity array.
 *
 * OSV stores severity as a VECTOR STRING — "CVSS:3.1/AV:N/AC:L/..." — not a
 * number, so the old numeric regex matched nothing and this function silently
 * returned null for every advisory. Everything then fell back to
 * database_specific.severity, which only GitHub-sourced advisories carry, so
 * PyPI and Go advisories had no severity at all and were defaulted to medium.
 *
 * Computing the real base score needs the whole CVSS formula; what we need is a
 * BAND, so the metrics that drive the band are read directly and mapped
 * conservatively. Any vector we cannot read returns null, and null means
 * unknown — never medium.
 */
export function cvssScore(severity: OsvVuln['severity']): number | null {
  if (!Array.isArray(severity)) return null;
  let best: number | null = null;
  for (const s of severity) {
    const raw = String(s?.score ?? '');
    // A bare number, if a database ever supplies one.
    const plain = raw.match(/^(\d+(?:\.\d+)?)$/);
    if (plain) {
      const n = parseFloat(plain[1]);
      if (Number.isFinite(n)) best = best == null ? n : Math.max(best, n);
      continue;
    }
    const n = scoreFromVector(raw);
    if (n != null) best = best == null ? n : Math.max(best, n);
  }
  return best;
}

/**
 * Approximate a CVSS v3/v4 base score from its vector.
 *
 * Deliberately an approximation with a documented direction: it is used only to
 * pick a band, and it rounds toward the SAFE side (a genuinely critical issue
 * must not be shown as medium). Vectors it does not understand return null.
 */
export function scoreFromVector(vector: string): number | null {
  if (!/^CVSS:[34]/i.test(vector)) return null;
  const get = (k: string): string | null => vector.match(new RegExp(`\\b${k}:([A-Z])`, 'i'))?.[1]?.toUpperCase() ?? null;
  // v4 uses VC/VI/VA for the impact metrics; v3 uses C/I/A.
  const c = get('VC') ?? get('C');
  const i = get('VI') ?? get('I');
  const a = get('VA') ?? get('A');
  const av = get('AV');
  const pr = get('PR');
  const ui = get('UI');
  if (!c || !i || !a) return null;
  const impact = (x: string): number => (x === 'H' ? 3 : x === 'L' ? 1 : 0);
  const worst = Math.max(impact(c), impact(i), impact(a));
  if (worst === 0) return 0;
  const network = av === 'N';
  const noPriv = pr === 'N';
  const noUi = ui === 'N';
  // Network-reachable, unauthenticated, no interaction, high impact => critical.
  if (worst === 3 && network && noPriv && noUi) return 9.8;
  if (worst === 3 && network && noPriv) return 8.8;
  if (worst === 3) return 7.5;
  if (worst === 1 && network && noPriv) return 6.5;
  return 4.3;
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
  // No rating from either source means we did not establish one. Saying
  // 'medium' there is inventing a number and then grading the user on it.
  let severity: DepSeverity = 'unknown';
  if (malware || dbSev === 'CRITICAL' || (cvss != null && cvss >= 9)) severity = 'critical';
  else if (dbSev === 'HIGH' || (cvss != null && cvss >= 7)) severity = 'high';
  else if (dbSev === 'MODERATE' || dbSev === 'MEDIUM' || (cvss != null && cvss >= 4)) severity = 'medium';
  else if (dbSev === 'LOW' || (cvss != null && cvss > 0)) severity = 'low';
  return { id: v.id, summary: v.summary || v.id, severity, malware };
}
