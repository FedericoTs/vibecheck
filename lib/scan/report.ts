import type { SupabaseScanResult, Grade } from './types';
import type { HeadersScanResult } from './headers';
import type { PathsScanResult } from './paths';
import type { SecretsScanResult } from './secrets';
import type { FundamentalsResult } from './fundamentals';
import type { LighthouseResult } from './lighthouse';
import { worstGrade } from './grade';

export type CategoryGroup = 'security' | 'basics' | 'performance';

export interface ReportCategory {
  key: string;
  group: CategoryGroup;
  label: string;
  grade: Grade | null; // null = ran but errored (not counted toward the overall grade)
  summary: string;
  findings: string[];
}

export interface Report {
  /** The headline grade — SECURITY only. Basics/performance never drag it. */
  overallGrade: Grade;
  verdict: string;
  issueCount: number; // security issues only
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
  A: 'Locked down. Nothing obvious a stranger can reach.',
  B: 'Mostly solid — a couple of gaps worth closing.',
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
      categories.push({
        key: 'supabase',
        group: 'security',
        label: 'Database exposure',
        grade: sb.grade,
        summary: sb.summary,
        findings: exposed.map(
          (f) => `${f.table} — ${f.rowsVisible != null ? `${f.rowsVisible.toLocaleString()} rows` : 'rows'} readable by anyone`,
        ),
      });
    } else {
      categories.push({ key: 'supabase', group: 'security', label: 'Database exposure', grade: null, summary: sb.error ?? 'Could not scan', findings: [] });
    }
  }
  if (inp.secrets) {
    const s = inp.secrets;
    issueCount += s.findings.length;
    securityGrades.push(s.grade);
    categories.push({ key: 'secrets', group: 'security', label: 'Exposed secrets', grade: s.grade, summary: s.summary, findings: s.findings.map((f) => `${f.label} — ${f.redacted}`) });
  }
  if (inp.paths) {
    const p = inp.paths;
    issueCount += p.exposed.length;
    securityGrades.push(p.grade);
    categories.push({ key: 'paths', group: 'security', label: 'Exposed files', grade: p.grade, summary: p.summary, findings: p.exposed.map((f) => `${f.label} — publicly served`) });
  }
  if (inp.headers) {
    const h = inp.headers;
    issueCount += h.missing.length;
    securityGrades.push(h.grade);
    categories.push({ key: 'headers', group: 'security', label: 'Security headers', grade: h.grade, summary: h.summary, findings: h.missing.map((c) => `${c.label} — ${c.fix}`) });
  }

  // ── basics + performance (secondary — own grades, never drag security) ─
  if (inp.fundamentals) {
    const f = inp.fundamentals;
    categories.push({ key: 'fundamentals', group: 'basics', label: 'Fundamentals', grade: f.grade, summary: f.summary, findings: f.failed.map((c) => `${c.label} — ${c.fix}`) });
  }
  if (inp.lighthouse) {
    const l = inp.lighthouse;
    categories.push({ key: 'lighthouse', group: 'performance', label: 'Performance & quality', grade: l.grade, summary: l.summary, findings: l.low.map((x) => `${x.label} — ${x.score}/100`) });
  }

  const overallGrade = worstGrade(securityGrades);
  return { overallGrade, verdict: VERDICT[overallGrade], issueCount, categories };
}
