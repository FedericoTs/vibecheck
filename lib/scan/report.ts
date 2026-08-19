import type { SupabaseScanResult, Grade } from './types';
import type { HeadersScanResult } from './headers';
import type { PathsScanResult } from './paths';
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
import { worstGrade } from './grade';

export type CategoryGroup = 'security' | 'privacy' | 'visibility' | 'basics' | 'performance';

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
  firebase?: FirebaseScanResult | null;
  routes?: RoutesScanResult | null;
  ai?: AiSurfaceResult | null;
  privacy?: PrivacyResult | null;
  email?: EmailAuthResult | null;
  transport?: TransportResult | null;
  visibility?: VisibilityResult | null;
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
      });
    }
    for (const c of f.collections) {
      checks.push({
        label: `${c.collection} (Firestore)`,
        pass: !c.exposed,
        detail: c.exposed ? 'documents readable by anyone' : 'not readable by anonymous visitors',
      });
    }
    categories.push({ key: 'firebase', group: 'security', label: 'Firebase exposure', grade: f.grade, summary: f.summary, checks });
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
      const n = s.sourceMaps.exposed.length;
      if (n > 0) issueCount += n;
      checks.push({
        label: 'Source maps not published',
        pass: n === 0,
        detail:
          n === 0
            ? 'your original source is not downloadable'
            : `${n} .map file(s) served — anyone can read your original source: ${s.sourceMaps.exposed.slice(0, 2).join(', ')}`,
      });
    }
    categories.push({ key: 'secrets', group: 'security', label: 'Exposed secrets', grade: s.grade, summary: s.summary, checks });
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
        }))
      : [{ label: 'No admin or debug routes reachable', pass: true, detail: `${r.findings.length} common paths checked` }];
    categories.push({ key: 'routes', group: 'security', label: 'Admin & debug routes', grade: r.grade, summary: r.summary, checks });
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
    const checks: CheckItem[] = h.checks.map((c) => ({ label: c.label, pass: c.present, detail: c.present ? undefined : 'not set on your responses' }));
    categories.push({ key: 'headers', group: 'security', label: 'Security headers', grade: h.grade, summary: h.summary, checks });
  }

  // ── basics + performance (secondary — own grades, never drag security) ─
  if (inp.transport && inp.transport.checks.length > 0) {
    const t = inp.transport;
    issueCount += t.failed.length;
    securityGrades.push(t.grade);
    const checks: CheckItem[] = t.checks.map((c) => ({ label: c.label, pass: c.pass, detail: c.detail }));
    categories.push({ key: 'transport', group: 'security', label: 'HTTPS & redirects', grade: t.grade, summary: t.summary, checks });
  }

  if (inp.email) {
    const e = inp.email;
    issueCount += e.failed.length;
    securityGrades.push(e.grade);
    const checks: CheckItem[] = e.checks.map((c) => ({ label: c.label, pass: c.pass, detail: c.detail }));
    categories.push({ key: 'email', group: 'security', label: 'Email spoofing protection', grade: e.grade, summary: e.summary, checks });
  }

  if (inp.privacy) {
    const pr = inp.privacy;
    // Own group, own grade: EU privacy is NOT a security finding, and must not
    // drag the security headline (nor be dragged by it).
    const checks: CheckItem[] = pr.checks.map((c) => ({ label: c.label, pass: c.pass, detail: c.detail }));
    categories.push({ key: 'privacy', group: 'privacy', label: 'EU privacy (GDPR signals)', grade: pr.grade, summary: pr.summary, checks });
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
