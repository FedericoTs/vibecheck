import type { SupabaseScanResult, Grade } from './types';
import type { HeadersScanResult } from './headers';
import type { PathsScanResult } from './paths';
import type { SecretsScanResult } from './secrets';
import type { FundamentalsResult } from './fundamentals';
import type { LighthouseResult } from './lighthouse';
import { worstGrade } from './grade';

export type CategoryGroup = 'security' | 'basics' | 'performance';

/** One thing the tool checked, and whether it passed. Shown as a ✓/✗ line. */
export interface CheckItem {
  label: string;
  pass: boolean;
  detail?: string;
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
}

const VERDICT: Record<Grade, string> = {
  A: 'Locked down. Nothing a stranger can reach.',
  B: 'Solid — a couple of gaps worth closing.',
  C: 'Some real gaps. Worth a look before you share this app around.',
  D: 'Leaky. A curious visitor can get further than you think.',
  F: 'Wide open. Anyone can read your data or walk through the front door.',
};

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
              ? `${f.rowsVisible != null ? `${f.rowsVisible.toLocaleString()} rows` : 'rows'} readable by anyone`
              : 'not readable by the anon key',
          }))
        : [{ label: 'No tenant tables reachable to test', pass: true }];
      categories.push({ key: 'supabase', group: 'security', label: 'Database exposure', grade: sb.grade, summary: sb.summary, checks });
    } else {
      categories.push({ key: 'supabase', group: 'security', label: 'Database exposure', grade: null, summary: sb.error ?? 'Could not scan', checks: [] });
    }
  }
  if (inp.secrets) {
    const s = inp.secrets;
    issueCount += s.findings.length;
    securityGrades.push(s.grade);
    const checks: CheckItem[] = s.findings.length
      ? s.findings.map((f) => ({ label: f.label, pass: false, detail: f.redacted }))
      : [
          {
            label: 'No secret keys in the client bundle',
            pass: true,
            detail: 'checked the HTML + JS for service_role, Stripe, AWS, OpenAI, Anthropic, GitHub & private keys',
          },
        ];
    categories.push({ key: 'secrets', group: 'security', label: 'Exposed secrets', grade: s.grade, summary: s.summary, checks });
  }
  if (inp.paths) {
    const p = inp.paths;
    issueCount += p.exposed.length;
    securityGrades.push(p.grade);
    const checks: CheckItem[] = p.findings.map((f) => ({ label: f.label, pass: !f.exposed, detail: f.exposed ? 'publicly served' : undefined }));
    categories.push({ key: 'paths', group: 'security', label: 'Exposed files', grade: p.grade, summary: p.summary, checks });
  }
  if (inp.headers) {
    const h = inp.headers;
    issueCount += h.missing.length;
    securityGrades.push(h.grade);
    const checks: CheckItem[] = h.checks.map((c) => ({ label: c.label, pass: c.present, detail: c.present ? undefined : c.fix }));
    categories.push({ key: 'headers', group: 'security', label: 'Security headers', grade: h.grade, summary: h.summary, checks });
  }

  // ── basics + performance (secondary — own grades, never drag security) ─
  if (inp.fundamentals) {
    const f = inp.fundamentals;
    const checks: CheckItem[] = f.checks.map((c) => ({ label: c.label, pass: c.pass, detail: c.pass ? undefined : c.fix }));
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
