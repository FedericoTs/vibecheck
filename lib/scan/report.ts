import type { SupabaseScanResult, Grade } from './types';
import type { HeadersScanResult } from './headers';
import type { PathsScanResult } from './paths';
import type { SecretsScanResult } from './secrets';
import { worstGrade } from './grade';

export interface ReportCategory {
  key: 'supabase' | 'secrets' | 'paths' | 'headers';
  label: string;
  grade: Grade | null; // null = ran but errored (not counted toward the overall grade)
  summary: string;
  findings: string[];
}

export interface Report {
  overallGrade: Grade;
  verdict: string;
  issueCount: number;
  categories: ReportCategory[];
}

const VERDICT: Record<Grade, string> = {
  A: 'Locked down. Nothing obvious a stranger can reach.',
  B: 'Mostly solid — a couple of gaps worth closing.',
  C: 'Some real gaps. Worth a look before you share this app around.',
  D: 'Leaky. A curious visitor can get further than you think.',
  F: 'Wide open. Anyone can read your data or walk through the front door.',
};

/** Merge the scans into one report card. Only categories with a real grade count toward the overall. */
export function combineReport(
  sb: SupabaseScanResult | null,
  hdr: HeadersScanResult | null,
  paths: PathsScanResult | null = null,
  secrets: SecretsScanResult | null = null,
): Report {
  const categories: ReportCategory[] = [];
  const graded: Grade[] = [];
  let issueCount = 0;

  // Ordered most-severe first: data, secret keys, exposed files, headers.
  if (sb) {
    if (sb.ok) {
      const exposed = sb.findings.filter((f) => f.exposed);
      issueCount += exposed.length;
      graded.push(sb.grade);
      categories.push({
        key: 'supabase',
        label: 'Database exposure',
        grade: sb.grade,
        summary: sb.summary,
        findings: exposed.map(
          (f) => `${f.table} — ${f.rowsVisible != null ? `${f.rowsVisible.toLocaleString()} rows` : 'rows'} readable by anyone`,
        ),
      });
    } else {
      categories.push({ key: 'supabase', label: 'Database exposure', grade: null, summary: sb.error ?? 'Could not scan', findings: [] });
    }
  }

  if (secrets) {
    issueCount += secrets.findings.length;
    graded.push(secrets.grade);
    categories.push({
      key: 'secrets',
      label: 'Exposed secrets',
      grade: secrets.grade,
      summary: secrets.summary,
      findings: secrets.findings.map((f) => `${f.label} — ${f.redacted}`),
    });
  }

  if (paths) {
    issueCount += paths.exposed.length;
    graded.push(paths.grade);
    categories.push({
      key: 'paths',
      label: 'Exposed files',
      grade: paths.grade,
      summary: paths.summary,
      findings: paths.exposed.map((f) => `${f.label} — publicly served`),
    });
  }

  if (hdr) {
    issueCount += hdr.missing.length;
    graded.push(hdr.grade);
    categories.push({
      key: 'headers',
      label: 'Security headers',
      grade: hdr.grade,
      summary: hdr.summary,
      findings: hdr.missing.map((c) => `${c.label} — ${c.fix}`),
    });
  }

  const overallGrade = worstGrade(graded);
  return { overallGrade, verdict: VERDICT[overallGrade], issueCount, categories };
}
