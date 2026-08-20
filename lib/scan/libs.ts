import type { Grade } from './types';

/**
 * Known-vulnerable front-end library detection — the retire.js / Snyk idea, run
 * against the bundle a live app already ships.
 *
 * Trust rules, because a false "you're vulnerable" is worse than silence:
 *  - We only ever flag a library when we can read an ACTUAL version from a
 *    filename (jquery-3.4.1.min.js) or a version banner (`jQuery v3.4.1`). We
 *    never guess from a minified blob, so an undetectable version is reported as
 *    nothing, not as a vulnerability.
 *  - Every finding cites real, published advisories (CVE ids) and the exact
 *    version that fixes it. The ranges below come from the CVE records / the
 *    retire.js dataset, not from vibes.
 *  - It reads only what the page already serves — it does not execute anything.
 */

export type LibSeverity = 'critical' | 'high' | 'medium' | 'low';

export interface LibFinding {
  library: string;
  version: string;
  severity: LibSeverity;
  cves: string[];
  summary: string;
  fixedIn: string;
}

export interface LibsScanResult {
  host: string;
  detected: number;
  findings: LibFinding[];
  grade: Grade;
  summary: string;
}

interface Vuln {
  below: string; // fixed in this version — anything earlier (within range) is vulnerable
  atOrAbove?: string; // range floor, to keep 0.x and 1.x advisories separate
  severity: LibSeverity;
  cves: string[];
  summary: string;
}
interface Sig {
  name: string;
  detect: RegExp[]; // each captures a version in group 1
  vulns: Vuln[];
}

// Curated, advisory-backed signatures for widely-shipped, reliably-detectable libs.
const SIGS: Sig[] = [
  {
    name: 'jQuery',
    detect: [
      /jquery[-.]?(\d+\.\d+(?:\.\d+)?)(?:\.slim)?(?:\.min)?\.js/i,
      /jQuery(?: JavaScript Library)? v(\d+\.\d+(?:\.\d+)?)/,
    ],
    vulns: [
      { below: '3.5.0', atOrAbove: '1.0.3', severity: 'high', cves: ['CVE-2020-11022', 'CVE-2020-11023'], summary: 'Cross-site scripting (XSS) via jQuery.htmlPrefilter when untrusted HTML reaches DOM-manipulation methods.' },
      { below: '3.4.0', atOrAbove: '1.0.0', severity: 'medium', cves: ['CVE-2019-11358'], summary: 'Prototype pollution via jQuery.extend(true, {}, …).' },
    ],
  },
  {
    name: 'jQuery UI',
    detect: [/jquery[-.]?ui[-.]?(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js/i, /jQuery UI(?: - v| v)(\d+\.\d+(?:\.\d+)?)/],
    vulns: [
      { below: '1.13.0', atOrAbove: '1.0.0', severity: 'medium', cves: ['CVE-2021-41182', 'CVE-2021-41183', 'CVE-2021-41184'], summary: 'XSS through the altField / of / other widget options accepting untrusted values.' },
    ],
  },
  {
    name: 'Bootstrap',
    detect: [/bootstrap[-.]?(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.(?:js|css)/i, /Bootstrap v(\d+\.\d+(?:\.\d+)?)/],
    vulns: [
      { below: '4.3.1', atOrAbove: '4.0.0', severity: 'medium', cves: ['CVE-2019-8331'], summary: 'XSS in the tooltip / popover data-attributes.' },
      { below: '3.4.1', atOrAbove: '3.0.0', severity: 'medium', cves: ['CVE-2019-8331', 'CVE-2018-14041'], summary: 'XSS in tooltip/popover data-attributes and the scrollspy target.' },
    ],
  },
  {
    name: 'Lodash',
    detect: [/lodash[-.]?(\d+\.\d+\.\d+)(?:\.min)?\.js/i, /lodash[\s\S]{0,120}?VERSION\s*=\s*['"](\d+\.\d+\.\d+)['"]/i],
    vulns: [
      { below: '4.17.21', atOrAbove: '3.0.0', severity: 'high', cves: ['CVE-2021-23337', 'CVE-2020-28500'], summary: 'Command injection via _.template() and ReDoS in _.toNumber / _.trim.' },
      { below: '4.17.12', atOrAbove: '3.0.0', severity: 'high', cves: ['CVE-2019-10744'], summary: 'Prototype pollution via _.defaultsDeep().' },
    ],
  },
  {
    name: 'Moment.js',
    detect: [/moment[-.]?(\d+\.\d+\.\d+)(?:\.min)?\.js/i, /\/\/!? moment\.js[\s\S]{0,60}?version\s*[:=]\s*['"]?(\d+\.\d+\.\d+)/i],
    vulns: [
      { below: '2.29.4', atOrAbove: '1.0.0', severity: 'high', cves: ['CVE-2022-31129', 'CVE-2022-24785'], summary: 'ReDoS on long date strings and path traversal when locales are loaded from user input.' },
    ],
  },
  {
    name: 'AngularJS',
    detect: [/angular[-.]?(1\.\d+(?:\.\d+)?)(?:\.min)?\.js/i, /AngularJS v(1\.\d+(?:\.\d+)?)/],
    vulns: [
      { below: '1.8.3', atOrAbove: '1.0.0', severity: 'high', cves: ['CVE-2020-7676', 'CVE-2022-25869'], summary: 'XSS via attribute/SVG handling. AngularJS 1.x is also end-of-life and no longer patched.' },
    ],
  },
  {
    name: 'Handlebars',
    detect: [/handlebars[-.]?(\d+\.\d+\.\d+)(?:\.min)?\.js/i, /Handlebars[\s\S]{0,40}?VERSION\s*=\s*["'](\d+\.\d+\.\d+)/],
    vulns: [
      { below: '4.7.7', atOrAbove: '4.0.0', severity: 'critical', cves: ['CVE-2021-23369', 'CVE-2021-23383'], summary: 'Remote code execution via prototype pollution when compiling templates with options.' },
    ],
  },
  {
    name: 'axios',
    detect: [/axios[-.]?(\d+\.\d+\.\d+)(?:\.min)?\.js/i, /axios\/(\d+\.\d+\.\d+)/],
    vulns: [
      { below: '1.6.0', atOrAbove: '1.0.0', severity: 'medium', cves: ['CVE-2023-45857'], summary: 'CSRF — the XSRF token can leak to third-party hosts through redirects.' },
      { below: '0.21.2', atOrAbove: '0.0.0', severity: 'high', cves: ['CVE-2020-28168', 'CVE-2021-3749'], summary: 'Server-side request forgery via proxy bypass, and ReDoS in trim().' },
    ],
  },
];

const SEV_RANK: Record<LibSeverity, number> = { critical: 4, high: 3, medium: 2, low: 1 };

// CDN / bundler version forms the filename patterns miss: unpkg `jquery@3.4.1`,
// cdnjs / Google `.../jquery/3.4.1/…`. The lookahead keeps the version a whole
// segment so we never grab a partial number.
const CDN: Array<[RegExp, string]> = [
  [/jquery-ui(?:\.js)?[@/](\d+\.\d+(?:\.\d+)?)(?=[/"'?)\s]|$)/i, 'jQuery UI'],
  [/jquery(?:\.js)?[@/](\d+\.\d+(?:\.\d+)?)(?=[/"'?)\s]|$)/i, 'jQuery'],
  [/bootstrap(?:\.js)?[@/](\d+\.\d+(?:\.\d+)?)(?=[/"'?)\s]|$)/i, 'Bootstrap'],
  [/lodash(?:\.js)?[@/](\d+\.\d+\.\d+)(?=[/"'?)\s]|$)/i, 'Lodash'],
  [/moment(?:\.js)?[@/](\d+\.\d+\.\d+)(?=[/"'?)\s]|$)/i, 'Moment.js'],
  [/angular(?:\.js)?[@/](1\.\d+(?:\.\d+)?)(?=[/"'?)\s]|$)/i, 'AngularJS'],
  [/handlebars(?:\.js)?[@/](\d+\.\d+\.\d+)(?=[/"'?)\s]|$)/i, 'Handlebars'],
  [/axios(?:\.js)?[@/](\d+\.\d+\.\d+)(?=[/"'?)\s]|$)/i, 'axios'],
];

/** Numeric version compare. Missing parts count as 0. Returns -1 / 0 / 1. */
export function cmpVersion(a: string, b: string): number {
  const pa = a.split('.').map((n) => parseInt(n, 10) || 0);
  const pb = b.split('.').map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d !== 0) return d < 0 ? -1 : 1;
  }
  return 0;
}

/** The first readable version for each library present in the served code. */
export function detectLibraries(text: string): Array<{ name: string; version: string }> {
  const out: Array<{ name: string; version: string }> = [];
  for (const sig of SIGS) {
    for (const re of sig.detect) {
      const m = text.match(re);
      if (m?.[1]) {
        out.push({ name: sig.name, version: m[1] });
        break; // first hit per library is enough
      }
    }
  }
  // CDN / bundler version forms, only for libraries not already found by filename/banner.
  const found = new Set(out.map((o) => o.name));
  for (const [re, name] of CDN) {
    if (found.has(name)) continue;
    const m = text.match(re);
    if (m?.[1]) {
      out.push({ name, version: m[1] });
      found.add(name);
    }
  }
  return out;
}

/** Turn detected versions into advisory-backed findings (one per vulnerable lib). */
export function assessLibraries(text: string): { detected: number; findings: LibFinding[] } {
  const detected = detectLibraries(text);
  const findings: LibFinding[] = [];
  for (const { name, version } of detected) {
    const sig = SIGS.find((s) => s.name === name)!;
    const hits = sig.vulns.filter(
      (v) => cmpVersion(version, v.below) < 0 && (!v.atOrAbove || cmpVersion(version, v.atOrAbove) >= 0),
    );
    if (hits.length === 0) continue;
    const worst = hits.reduce((a, b) => (SEV_RANK[b.severity] > SEV_RANK[a.severity] ? b : a));
    const cves = [...new Set(hits.flatMap((h) => h.cves))];
    const fixedIn = hits.reduce((a, b) => (cmpVersion(b.below, a) > 0 ? b.below : a), '0.0.0');
    findings.push({ library: name, version, severity: worst.severity, cves, summary: worst.summary, fixedIn });
  }
  findings.sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity]);
  return { detected: detected.length, findings };
}

export function gradeLibs(findings: LibFinding[]): Grade {
  if (findings.some((f) => f.severity === 'critical')) return 'D';
  if (findings.some((f) => f.severity === 'high')) return 'C';
  if (findings.length > 0) return 'B';
  return 'A';
}

/** Full result for the report. Pure — the fetch happens in the route. */
export function scanLibraries(text: string, host: string): LibsScanResult {
  const { detected, findings } = assessLibraries(text);
  const grade = gradeLibs(findings);
  const summary =
    findings.length > 0
      ? `${findings.length} outdated librar${findings.length === 1 ? 'y' : 'ies'} with known vulnerabilities`
      : detected > 0
        ? `${detected} JavaScript librar${detected === 1 ? 'y' : 'ies'} detected — none with known vulnerabilities`
        : 'No detectable third-party JavaScript libraries';
  return { host, detected, findings, grade, summary };
}
