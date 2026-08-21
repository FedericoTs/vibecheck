import type { SupabaseScanResult, Grade } from './types';
import type { HeadersScanResult } from './headers';
import type { PathsScanResult } from './paths';
import { fileEvidence, routeEvidence, headerEvidence, dnsEvidence, sourceMapEvidence, tableEvidence, type CheckEvidence } from './evidence';
import { isGradedSecret, isHardSecret } from './secrets';
import type { SecretsScanResult } from './secrets';
import type { FundamentalsResult } from './fundamentals';
import type { LighthouseResult } from './lighthouse';
import type { FirebaseScanResult } from './firebase';
import type { RoutesScanResult } from './routes';
import type { AiSurfaceResult } from './ai-surface';
import type { PrivacyResult } from './privacy';
import type { EmailAuthResult } from './email-auth';
import type { TransportResult } from './transport';
import type { VisibilityResult } from './visibility';
import type { SmugglingResult } from './smuggling';
import type { DevServerResult } from './devserver';
import type { ScaffoldResult } from './scaffold';
import type { LibsScanResult } from './libs';
import { worstGrade } from './grade';

export type CategoryGroup = 'security' | 'privacy' | 'visibility' | 'basics' | 'performance';

/** One thing the tool checked, and whether it passed. Shown as a ✓/✗ line. */
export type Severity = 'critical' | 'high' | 'medium' | 'low';

export interface CheckItem {
  label: string;
  pass: boolean;
  detail?: string;
  /** Only meaningful on a FAILING check — how much it actually matters. */
  severity?: Severity;
  /**
   * False when a finding is SHOWN but must not move the grade or the issue
   * count — the crawler-matrix and repo-mode precedent. Used where a legitimate
   * explanation exists that we cannot rule out from outside, so an accusation
   * would be unearned. Absent means graded, so existing checks are unaffected.
   */
  graded?: boolean;
  /**
   * The literal request that produced this result, so a finding is reproducible
   * rather than asserted. Never contains a credential: keys travel as headers,
   * and any key involved is the user's own publishable one.
   */
  evidence?: CheckEvidence;
}

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low'];

/**
 * Failing SECURITY checks grouped by severity. Nine issues is not nine equal
 * problems: one readable users table outweighs a missing Referrer-Policy, and a
 * flat count hides that.
 */
export function severityCounts(report: Report): Record<Severity, number> {
  const out: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const c of report.categories) {
    if (c.group !== 'security') continue;
    for (const check of c.checks) {
      if (check.pass) continue;
      if (check.graded === false) continue; // reported, but not an accusation
      out[check.severity ?? 'medium'] += 1;
    }
  }
  return out;
}

export interface ReportCategory {
  key: string;
  group: CategoryGroup;
  label: string;
  grade: Grade | null; // null = ran but errored (not counted toward the overall grade)
  summary: string;
  checks: CheckItem[];
}

export interface Report {
  /** The headline grade — SECURITY only. Basics/performance never drag it. */
  overallGrade: Grade;
  verdict: string;
  issueCount: number; // failing security checks
  passed: number; // passing checks across everything (shows the depth)
  total: number; // all checks run
  categories: ReportCategory[];
}

export interface ReportInputs {
  supabase?: SupabaseScanResult | null;
  headers?: HeadersScanResult | null;
  paths?: PathsScanResult | null;
  secrets?: SecretsScanResult | null;
  fundamentals?: FundamentalsResult | null;
  lighthouse?: LighthouseResult | null;
  firebase?: FirebaseScanResult | null;
  routes?: RoutesScanResult | null;
  ai?: AiSurfaceResult | null;
  privacy?: PrivacyResult | null;
  email?: EmailAuthResult | null;
  transport?: TransportResult | null;
  visibility?: VisibilityResult | null;
  libraries?: LibsScanResult | null;
  smuggling?: SmugglingResult | null;
  devServer?: DevServerResult | null;
  scaffold?: ScaffoldResult | null;
}

/** Column names that usually mean personal or payment data. */
const SENSITIVE_COLUMN = /^(email|phone|tel|mobile|address|street|postcode|zip|dob|birth|ssn|nino|tax|iban|card|stripe|customer_id|password|hash|token|secret|api_key|salary|latitude|longitude|ip_address)/i;

/** A short, human list of the exposed fields, leading with the sensitive ones. */
export function describeColumns(columns: string[]): string {
  const sensitive = columns.filter((c) => SENSITIVE_COLUMN.test(c));
  const shown = [...sensitive, ...columns.filter((c) => !sensitive.includes(c))].slice(0, 5);
  const more = columns.length - shown.length;
  const list = shown.join(', ') + (more > 0 ? ` +${more} more` : '');
  return sensitive.length > 0 ? `${list} (personal data)` : list;
}

const VERDICT: Record<Grade, string> = {
  A: 'Locked down. Nothing a stranger can reach.',
  B: 'Solid — a couple of gaps worth closing.',
  C: 'Some real gaps. Worth a look before you share this app around.',
  D: 'Leaky. A curious visitor can get further than you think.',
  F: 'Wide open. Anyone can read your data or walk through the front door.',
};

/**
 * The evidence builders return null when a value cannot be safely quoted; a
 * CheckItem wants undefined. Missing evidence is always acceptable — it degrades
 * a finding to the sentence it used to be, never to a wrong command.
 */
const ev = (e: CheckEvidence | null): CheckEvidence | undefined => e ?? undefined;

/** Merge the scans into one report card. The headline grade is security-only. */
export function combineReport(inp: ReportInputs): Report {
  const categories: ReportCategory[] = [];
  const securityGrades: Grade[] = [];
  let issueCount = 0;

  // ── security (drives the headline grade), most-severe first ──────────
  const sb = inp.supabase;
  if (sb) {
    if (sb.ok) {
      const exposed = sb.findings.filter((f) => f.exposed);
      issueCount += exposed.length;
      securityGrades.push(sb.grade);
      const checks: CheckItem[] = sb.findings.length
        ? sb.findings.map((f) => ({
            label: f.table,
            pass: !f.exposed,
            detail: f.exposed
              ? `${f.rowsVisible != null ? `${f.rowsVisible.toLocaleString()} rows` : 'rows'} readable by anyone` +
                (f.columns?.length ? ` — exposes ${describeColumns(f.columns)}` : '')
              : 'not readable by the anon key',
            severity: 'critical' as const,
            // Only an EXPOSED table gets the command. Handing someone a curl for
            // a table that is correctly locked down invites them to run it, see
            // a 401, and conclude the tool is broken.
            evidence: f.exposed && f.probeUrl ? ev(tableEvidence(f.probeUrl)) : undefined,
          }))
        : [{ label: 'No tables reachable to test', pass: true }];

      // Storage buckets
      if (sb.buckets?.checked) {
        const b = sb.buckets;
        if (b.enumerable) issueCount += 1 + b.publicBuckets.length;
        checks.push({
          label: 'Storage buckets',
          pass: !b.enumerable,
          detail: b.enumerable
            ? b.publicBuckets.length
              ? `anyone can list your buckets — ${b.publicBuckets.length} public: ${b.publicBuckets.slice(0, 3).join(', ')}`
              : 'anyone can enumerate your storage buckets'
            : 'not enumerable by anonymous visitors',
          severity: 'high',
        });
      }

      // Public database functions (listed, never called)
      if (sb.rpc?.checked) {
        const n = sb.rpc.exposed.length;
        checks.push({
          label: 'Public database functions',
          pass: n === 0,
          detail:
            n === 0
              ? 'none exposed on the public API'
              : `${n} callable by anyone: ${sb.rpc.exposed.slice(0, 4).join(', ')}${n > 4 ? '…' : ''}`,
          severity: 'medium',
        });
      }
      // Auth configuration: only the dangerous COMBINATION is a failure.
      if (sb.auth?.checked) {
        const a = sb.auth;
        const risky = a.autoConfirm && a.signupsOpen;
        if (risky) issueCount += 1;
        checks.push({
          label: 'Email confirmation required for new accounts',
          pass: !risky,
          detail: risky
            ? 'signups are open AND auto-confirmed — anyone can register as any email address without proving they own it'
            : a.autoConfirm
              ? 'auto-confirm is on, but signups are closed'
              : 'new accounts must confirm their email',
          severity: 'high',
        });
      }
      categories.push({ key: 'supabase', group: 'security', label: 'Database exposure', grade: sb.grade, summary: sb.summary, checks });
    } else {
      categories.push({ key: 'supabase', group: 'security', label: 'Database exposure', grade: null, summary: sb.error ?? 'Could not scan', checks: [] });
    }
  }
  if (inp.firebase?.ok) {
    const f = inp.firebase;
    issueCount += f.exposedCount + (f.rtdbOpen ? 1 : 0);
    securityGrades.push(f.grade);
    const checks: CheckItem[] = [];
    if (f.rtdbChecked) {
      checks.push({
        label: 'Realtime Database locked down',
        pass: !f.rtdbOpen,
        detail: f.rtdbOpen ? 'the entire database is readable by anyone' : 'not readable by anonymous visitors',
        severity: 'critical',
      });
    }
    for (const c of f.collections) {
      checks.push({
        label: `${c.collection} (Firestore)`,
        pass: !c.exposed,
        detail: c.exposed ? 'documents readable by anyone' : 'not readable by anonymous visitors',
        severity: 'critical',
      });
    }
    categories.push({ key: 'firebase', group: 'security', label: 'Firebase exposure', grade: f.grade, summary: f.summary, checks });
  }

  if (inp.secrets) {
    const s = inp.secrets;
    // Only findings that can move the grade count as issues. A localhost DSN is
    // reported, never counted — the same rule repo mode has always applied.
    issueCount += s.findings.filter(isGradedSecret).length;
    securityGrades.push(s.grade);
    const checks: CheckItem[] = s.findings.length
      ? s.findings.map((f) => {
          if (!isGradedSecret(f)) {
            return {
              label: `Local dev credentials (${f.label})`,
              pass: false,
              graded: false,
              severity: 'low' as const,
              detail: `${f.redacted} — points at a local or private host, so it is not reachable from the internet. Reported, not graded.`,
            };
          }
          if (!isHardSecret(f)) {
            return {
              label: `${f.label} on a commented-out line`,
              pass: false,
              severity: 'medium' as const,
              detail: `${f.redacted} — commenting it out did not un-publish it: these bytes are being served to anyone who fetches this file. Harmless if it was always a placeholder; rotate it if it was ever real.`,
            };
          }
          return {
            label: f.label,
            pass: false,
            detail: f.redacted,
            severity: f.severity === 'high' ? ('critical' as const) : f.severity,
          };
        })
      : [
          {
            label: 'No secret keys in the client bundle',
            pass: true,
            detail: 'checked the HTML + JS for service_role, Stripe, AWS, OpenAI, Anthropic, GitHub & private keys',
          },
        ];
    if (s.publicGoogleKeys) {
      // Advisory, never a failure: these keys are public by design. The real
      // question is whether they're referrer-restricted, which we can't see.
      checks.push({
        label: 'Google/Firebase keys are public by design',
        pass: true,
        detail: `${s.publicGoogleKeys} found — that's normal; just make sure they're restricted by HTTP referrer in Google Cloud`,
      });
    }
    if (s.sourceMaps?.checked) {
      const sm = s.sourceMaps;
      const n = sm.exposed.length;
      if (n > 0) issueCount += n;
      // Evidence-first, and precise about which of three states we are in: we
      // fetched and parsed a map; a map was referenced but did not resolve; or
      // nothing referenced one at all. The middle case used to be reported as a
      // clean pass, which claimed more than we had checked.
      const files = sm.firstPartyFiles ?? 0;
      const sample = (sm.sample ?? []).slice(0, 2).join(', ');
      // State what is retrievable, never that something "leaked". tldraw and
      // excalidraw serve working maps deliberately — they are open source. The
      // bytes are the same; only the owner knows whether that is intended, so
      // the finding reports the fact and names the fix without alleging harm.
      const detail =
        n > 0
          ? `${files > 0 ? `${files} original source file(s)` : 'your build output'} can be reconstructed from your production bundles` +
            (sample ? ` — including ${sample}` : '') +
            `. Intentional if your code is open source; otherwise set productionBrowserSourceMaps to false.`
          : (sm.annotated ?? 0) > 0
            ? `your chunks reference source maps, but none of the ${sm.annotated} we fetched resolved`
            : 'no source maps are referenced or served';
      checks.push({
        label: 'Source maps not published',
        pass: n === 0,
        detail,
        severity: 'medium',
        // The map URL, never the chunk URL: curling the chunk shows minified
        // JS, which would look like the opposite of the finding.
        evidence: n > 0 && sm.mapUrls?.length ? ev(sourceMapEvidence(sm.mapUrls[0])) : undefined,
      });
    }
    categories.push({ key: 'secrets', group: 'security', label: 'Exposed secrets', grade: s.grade, summary: s.summary, checks });
  }
  if (inp.libraries && (inp.libraries.detected > 0 || inp.libraries.findings.length > 0)) {
    const lb = inp.libraries;
    const checks: CheckItem[] = lb.findings.map((f) => ({
      label: `${f.library} ${f.version} — ${f.cves[0]}${f.cves.length > 1 ? ` +${f.cves.length - 1} more` : ''}`,
      pass: false,
      severity: f.severity,
      detail: `${f.summary} Patched in ${f.fixedIn}.`,
    }));
    if (lb.findings.length === 0) {
      checks.push({ label: `${lb.detected} librar${lb.detected === 1 ? 'y' : 'ies'} detected — no known vulnerabilities`, pass: true });
    }
    issueCount += lb.findings.length;
    securityGrades.push(lb.grade);
    categories.push({ key: 'libs', group: 'security', label: 'Vulnerable libraries', grade: lb.grade, summary: lb.summary, checks });
  }
  if (inp.ai) {
    const a = inp.ai;
    issueCount += a.exposed.length;
    securityGrades.push(a.grade);
    // Only surface what we learned something about; "absent" everywhere is noise.
    const interesting = a.findings.filter((f) => f.verdict !== 'absent');
    const checks: CheckItem[] = interesting.length
      ? interesting.map((f) => ({
          label: f.label,
          pass: f.verdict !== 'exposed',
          detail: f.verdict === 'inconclusive' ? `couldn't be determined — ${f.detail}` : f.detail,
          severity: 'high' as const,
        }))
      : [{ label: 'No exposed AI or MCP endpoints', pass: true, detail: `${a.findings.length} common AI endpoints checked` }];
    categories.push({ key: 'ai', group: 'security', label: 'AI & MCP endpoints', grade: a.grade, summary: a.summary, checks });
  }

  if (inp.routes) {
    const r = inp.routes;
    issueCount += r.exposed.length;
    securityGrades.push(r.grade);
    // Only report routes we actually learned something about — listing ten
    // "absent" paths would be noise, and "inconclusive" is not an accusation.
    const interesting = r.findings.filter((f) => f.verdict !== 'absent');
    const checks: CheckItem[] = interesting.length
      ? interesting.map((f) => ({
          label: f.label,
          pass: f.verdict !== 'exposed',
          detail: f.verdict === 'inconclusive' ? `couldn't be determined — ${f.detail}` : f.detail,
          severity: f.kind === 'data' ? ('critical' as const) : f.kind === 'admin' ? ('high' as const) : ('medium' as const),
          evidence: f.verdict === 'exposed' ? ev(routeEvidence(r.host, f.path)) : undefined,
        }))
      : [{ label: 'No admin or debug routes reachable', pass: true, detail: `${r.findings.length} common paths checked` }];
    categories.push({ key: 'routes', group: 'security', label: 'Admin & debug routes', grade: r.grade, summary: r.summary, checks });
  }

  if (inp.paths) {
    const p = inp.paths;
    issueCount += p.exposed.length;
    securityGrades.push(p.grade);
    const checks: CheckItem[] = p.findings.map((f) => ({
      label: f.label,
      pass: !f.exposed,
      detail: f.exposed ? 'publicly served' : undefined,
      severity: f.severity,
      evidence: f.exposed ? ev(fileEvidence(p.host, f.path)) : undefined,
    }));
    categories.push({ key: 'paths', group: 'security', label: 'Exposed files', grade: p.grade, summary: p.summary, checks });
  }
  if (inp.headers) {
    const h = inp.headers;
    issueCount += h.missing.length;
    securityGrades.push(h.grade);
    const checks: CheckItem[] = h.checks.map((c) => ({
      label: c.label,
      pass: c.present,
      detail: c.present ? undefined : 'not set on your responses',
      severity: c.severity,
      evidence: c.present ? undefined : ev(headerEvidence(h.host, c.key)),
    }));
    categories.push({ key: 'headers', group: 'security', label: 'Security headers', grade: h.grade, summary: h.summary, checks });
  }

  // ── basics + performance (secondary — own grades, never drag security) ─
  if (inp.transport && inp.transport.checks.length > 0) {
    const t = inp.transport;
    issueCount += t.failed.length;
    securityGrades.push(t.grade);
    const checks: CheckItem[] = t.checks.map((c) => ({ label: c.label, pass: c.pass, detail: c.detail, severity: c.severity }));
    categories.push({ key: 'transport', group: 'security', label: 'HTTPS & redirects', grade: t.grade, summary: t.summary, checks });
  }

  if (inp.email) {
    const e = inp.email;
    issueCount += e.failed.length;
    securityGrades.push(e.grade);
    const checks: CheckItem[] = e.checks.map((c) => ({
      label: c.label,
      pass: c.pass,
      detail: c.detail,
      severity: c.severity,
      evidence: c.pass || !/^(spf|dmarc)$/.test(c.key) ? undefined : ev(dnsEvidence(e.host, c.key as 'spf' | 'dmarc')),
    }));
    categories.push({ key: 'email', group: 'security', label: 'Email spoofing protection', grade: e.grade, summary: e.summary, checks });
  }

  if (inp.privacy) {
    const pr = inp.privacy;
    // Own group, own grade: EU privacy is NOT a security finding, and must not
    // drag the security headline (nor be dragged by it).
    const checks: CheckItem[] = pr.checks.map((c) => ({ label: c.label, pass: c.pass, detail: c.detail }));
    categories.push({ key: 'privacy', group: 'privacy', label: 'EU privacy (GDPR signals)', grade: pr.grade, summary: pr.summary, checks });
  }

  // Development-mode build artifacts. Worded carefully: a static mirror of a
  // dev-served page reproduces these bytes exactly, so we report what is being
  // SERVED and never diagnose what is RUNNING.
  if (inp.devServer && inp.devServer.verdict !== 'unknown') {
    const ds = inp.devServer;
    const found = ds.verdict === 'dev-artifacts';
    if (found) issueCount += 1;
    securityGrades.push(found ? 'F' : 'A');
    categories.push({
      key: 'devserver',
      group: 'security',
      label: 'Production build',
      grade: found ? 'F' : 'A',
      summary: found
        ? 'Development build artifacts are being served publicly'
        : 'This is a production build ✅',
      checks: [
        {
          label: 'Serving a production build, not a development one',
          pass: !found,
          detail: found
            ? `${ds.reason}. A development build ships unminified source, prints file contents in stack traces, and has no CSP. Evidence: ${ds.signals[0]?.evidence ?? 'dev-only asset paths'}`
            : ds.reason,
          severity: 'high',
        },
      ],
    });
  }

  // Hidden instructions aimed at AI readers. Its own category because the
  // question it answers is not "are you exposed" but "does your page say
  // something to a machine that it does not say to a person".
  if (inp.smuggling) {
    const sm = inp.smuggling;
    const n = sm.payloads.length;
    if (n > 0) issueCount += n;
    const checks: CheckItem[] = [
      {
        label: 'No invisible instructions aimed at AI readers',
        pass: n === 0,
        // Evidence first: the decoded text IS the finding. Nobody should have to
        // take our word for it.
        detail:
          n > 0
            ? `${n} hidden instruction(s) found in your page, invisible in a browser but readable by an AI. First one decodes to: "${sm.payloads[0].decoded.slice(0, 120)}"`
            : sm.limitedCoverage
              ? 'none in the served HTML — but most of this page is drawn in the browser, which we do not run, so this is partial'
              : 'none — nothing in your page is hidden from human readers but visible to machines',
        severity: 'high',
      },
    ];
    if (sm.conformantResidue > 0) {
      checks.push({
        label: 'Emoji tag characters present',
        // Valid subdivision flags leave this residue when markup splits them,
        // and it cannot encode prose — reported so the number is never a
        // surprise, never graded because it has a legitimate explanation.
        pass: true,
        detail: `${sm.conformantResidue} tag character(s) in the emoji alphabet — normal on pages that show regional flags, and they cannot spell an instruction, so reported, not graded`,
      });
    }
    if (sm.invisibleControls > 0) {
      checks.push({
        label: 'Zero-width characters present',
        // Never a failure: ZWJ is required in emoji and in Arabic, Persian and
        // Indic scripts, and a stray BOM is a build artefact, not an attack.
        pass: true,
        detail: `${sm.invisibleControls} zero-width or bidi character(s) — normal in emoji and in Arabic/Persian/Indic text, so reported, not graded`,
      });
    }
    // A definite verdict moves the security headline; "limited coverage"
    // contributes nothing rather than being counted as a pass.
    if (n > 0) securityGrades.push('F');
    else if (!sm.limitedCoverage) securityGrades.push('A');
    categories.push({
      key: 'smuggling',
      group: 'security',
      label: 'Hidden AI instructions',
      grade: n > 0 ? 'F' : sm.limitedCoverage ? null : 'A',
      summary:
        n > 0
          ? `${n} instruction(s) hidden in your page, visible only to AI`
          : sm.limitedCoverage
            ? 'Limited coverage — this page is drawn in the browser'
            : 'Nothing hidden from humans but readable by machines ✅',
      checks,
    });
  }

  // Scaffold defaults sit in VISIBILITY, not security: the harm is that Google,
  // ChatGPT and every link preview are told the app is called "Create Next App".
  // Every existing audit ticks the box because a title is present — this is the
  // gap between present and correct.
  if (inp.scaffold && inp.scaffold.verdict !== 'unknown') {
    const sc = inp.scaffold;
    const hit = sc.finding;
    const graded = !!hit && hit.severity === 'warning';
    if (graded) issueCount += 1;
    categories.push({
      key: 'scaffold',
      group: 'visibility',
      label: 'Your app has its own name',
      grade: graded ? 'D' : 'A',
      summary: hit
        ? `Still shipping the ${hit.generator} default`
        : 'The page carries its own title and description ✅',
      checks: [
        {
          label: 'Title and description are yours, not the template default',
          // An informational hit (a published template demo, where the default
          // is correct) is reported without being counted against them.
          pass: !graded,
          detail: hit
            ? `${sc.reason}. Matched exactly: ${hit.fields.join('; ')}`
            : sc.reason,
          severity: 'medium',
        },
      ],
    });
  }

  if (inp.visibility) {
    const v = inp.visibility;
    const checks = v.checks.map((c) => ({ label: c.label, pass: c.pass, detail: c.detail }));
    categories.push({ key: 'visibility', group: 'visibility', label: 'AI & search visibility', grade: v.grade, summary: v.summary, checks });
  }

  if (inp.fundamentals) {
    const f = inp.fundamentals;
    const checks: CheckItem[] = f.checks.map((c) => ({ label: c.label, pass: c.pass, detail: c.pass ? undefined : 'missing from the page' }));
    categories.push({ key: 'fundamentals', group: 'basics', label: 'Fundamentals', grade: f.grade, summary: f.summary, checks });
  }
  if (inp.lighthouse) {
    const l = inp.lighthouse;
    const items: Array<[string, number | null]> = [
      ['Performance', l.scores.performance],
      ['Accessibility', l.scores.accessibility],
      ['Best practices', l.scores.bestPractices],
      ['SEO', l.scores.seo],
    ];
    const checks: CheckItem[] = items
      .filter((x): x is [string, number] => x[1] != null)
      .map(([label, score]) => ({ label, pass: score >= 90, detail: `${score}/100` }));
    categories.push({ key: 'lighthouse', group: 'performance', label: 'Performance & quality', grade: l.grade, summary: l.summary, checks });
  }

  const all = categories.flatMap((c) => c.checks);
  const overallGrade = worstGrade(securityGrades);
  return {
    overallGrade,
    verdict: VERDICT[overallGrade],
    issueCount,
    passed: all.filter((c) => c.pass).length,
    total: all.length,
    categories,
  };
}
