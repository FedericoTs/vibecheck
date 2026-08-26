/**
 * Turning a pile of checks into a document.
 *
 * The scan engine produces categories and checks. A reader needs something
 * else: what the headline actually means, what to do first, what we could not
 * determine, and what is already fine. All of that is derivable from the report
 * we already build — none of it needs another request — but until now it lived
 * only inside buildFixPrompt and buildReportMarkdown, which is why the
 * downloaded Markdown reads better than the page it came from.
 *
 * A rule this module holds to: NOTHING here invents a number. Every score it
 * surfaces is one a scanner actually computed, every count is a count of real
 * checks. Where a pillar has no single honest aggregate, it returns null rather
 * than averaging unlike things into a figure that looks precise and is not.
 */

import type { CategoryGroup, ReportCategory, CheckItem, Report, Severity } from './report';
import { SEVERITY_ORDER } from './report';
import type { Grade } from './types';

/* ── pillars ─────────────────────────────────────────────────────────── */

/**
 * The five groups, in the order a reader should meet them: what a stranger can
 * take, then what leaks about your visitors, then whether you can be found,
 * then whether the page is put together, then how fast it is.
 */
export const PILLAR_ORDER: CategoryGroup[] = ['security', 'privacy', 'accessibility', 'visibility', 'basics', 'performance'];

export const PILLAR_LABEL: Record<CategoryGroup, string> = {
  security: 'Security',
  privacy: 'Privacy',
  visibility: 'Findability',
  accessibility: 'Accessibility',
  basics: 'Fundamentals',
  performance: 'Performance',
};

/** One line on what the pillar is for — the reader may not know why it is here. */
export const PILLAR_BLURB: Record<CategoryGroup, string> = {
  security: 'What a stranger can reach without logging in. This is the only pillar that sets your grade.',
  privacy: 'What runs and what is collected before a visitor agrees to anything.',
  visibility: 'Whether search engines and AI answer engines can read and cite you.',
  accessibility:
    'Barriers we can prove from the markup you served. Automated checks catch roughly half of what matters, so passing here is not a claim of conformance.',
  basics: 'The hygiene a browser and a crawler both expect from any page.',
  performance: "Google's own measurement of how the page loads and behaves.",
};

const GRADE_ORDER: Grade[] = ['A', 'B', 'C', 'D', 'F'];

/** Worst of a set of grades — the same rule the headline uses, applied per pillar. */
function worstOf(grades: Grade[]): Grade | null {
  if (grades.length === 0) return null;
  return grades.reduce((worst, g) => (GRADE_ORDER.indexOf(g) > GRADE_ORDER.indexOf(worst) ? g : worst), 'A' as Grade);
}

export interface PillarView {
  group: CategoryGroup;
  label: string;
  blurb: string;
  /** Worst category grade in the pillar, or null when nothing in it graded. */
  grade: Grade | null;
  categories: ReportCategory[];
  /** Checks that failed and count against you. */
  failing: number;
  /** Checks shown but deliberately not graded — the honest "we could not tell". */
  unknown: number;
  passing: number;
}

/** Split a report into its five pillars, dropping any that ran nothing. */
export function pillars(report: Report): PillarView[] {
  return PILLAR_ORDER.map((group) => {
    const categories = report.categories.filter((c) => c.group === group);
    let failing = 0;
    let unknown = 0;
    let passing = 0;
    for (const c of categories) {
      for (const check of c.checks) {
        if (check.pass) passing += 1;
        else if (check.graded === false) unknown += 1;
        else failing += 1;
      }
    }
    return {
      group,
      label: PILLAR_LABEL[group],
      blurb: PILLAR_BLURB[group],
      grade: worstOf(categories.map((c) => c.grade).filter((g): g is Grade => g !== null)),
      categories,
      failing,
      unknown,
      passing,
    };
  }).filter((p) => p.categories.length > 0);
}

/* ── the priority queue ──────────────────────────────────────────────── */

/**
 * How urgent a severity is in plain words. Severity says how bad it is;
 * this says what to do about it on a Tuesday, which is the part people act on.
 */
export const SEVERITY_ACTION: Record<Severity, string> = {
  critical: 'fix before anyone else opens this app',
  high: 'fix before you share this app around',
  medium: 'fix during launch polish',
  low: 'tidy up when you have a spare hour',
};

export interface RankedFinding {
  /** 1-based position in the queue, so "start at the top" is literal. */
  rank: number;
  category: ReportCategory;
  check: CheckItem;
  severity: Severity;
  action: string;
}

/**
 * Every graded failure across every pillar, worst first.
 *
 * Ordered by severity, then by pillar (security ahead of the rest, because it
 * is the only pillar that moves the grade), then by the order the scanner
 * declared them so the sequence is stable between runs on the same site.
 */
export function ranked(report: Report): RankedFinding[] {
  const out: { category: ReportCategory; check: CheckItem; severity: Severity }[] = [];
  for (const category of report.categories) {
    for (const check of category.checks) {
      if (check.pass) continue;
      if (check.graded === false) continue; // an unknown is not an accusation
      out.push({ category, check, severity: check.severity ?? 'medium' });
    }
  }
  out.sort((a, b) => {
    const sev = SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
    if (sev !== 0) return sev;
    const grp = (a.category.group === 'security' ? 0 : 1) - (b.category.group === 'security' ? 0 : 1);
    if (grp !== 0) return grp;
    return 0;
  });
  return out.map((f, i) => ({ ...f, rank: i + 1, action: SEVERITY_ACTION[f.severity] }));
}

/**
 * Findings we showed but refused to grade, because a legitimate explanation
 * exists that we cannot rule out from outside.
 *
 * Surfaced as its own list rather than mixed in with real failures. A scanner
 * that says plainly what it could not determine earns more trust on what it
 * did determine, and burying these next to genuine problems loses that twice:
 * it reads as an accusation to the owner, and as noise to everyone else.
 */
export function unknowns(report: Report): { category: ReportCategory; check: CheckItem }[] {
  const out: { category: ReportCategory; check: CheckItem }[] = [];
  for (const category of report.categories) {
    for (const check of category.checks) {
      if (!check.pass && check.graded === false) out.push({ category, check });
    }
  }
  return out;
}

/* ── the verdict sentence ────────────────────────────────────────────── */

export interface Verdict {
  /** The canned line for the grade, straight from the report. */
  headline: string;
  /** "62 passed, 3 to fix, 1 we could not determine." */
  counts: string;
  /** Best-graded pillar, when there is a meaningful winner. */
  strongest: string | null;
  /** Worst-graded pillar, when something scored below the top. */
  weakest: string | null;
}

const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

/**
 * One sentence carrying verdict, counts, and where the reader should look.
 *
 * A letter on its own tells someone how to feel. This tells them what was
 * measured and which end of the report to start at.
 */
export function verdict(report: Report): Verdict {
  const ps = pillars(report);
  const unknownCount = ps.reduce((n, p) => n + p.unknown, 0);

  const parts = [plural(report.passed, 'check passed', 'checks passed'), `${report.issueCount} to fix`];
  if (unknownCount > 0) parts.push(`${unknownCount} we could not determine`);

  const graded = ps.filter((p) => p.grade !== null) as (PillarView & { grade: Grade })[];
  const byGrade = [...graded].sort((a, b) => GRADE_ORDER.indexOf(a.grade) - GRADE_ORDER.indexOf(b.grade));
  const best = byGrade[0];
  const worst = byGrade[byGrade.length - 1];

  // Only worth naming when they differ — "strongest and weakest: Security" is noise.
  const meaningful = byGrade.length > 1 && best.grade !== worst.grade;

  return {
    headline: report.verdict,
    counts: `${parts.join(', ')}.`,
    strongest: meaningful ? best.label : null,
    weakest: meaningful ? worst.label : null,
  };
}

/* ── what is already fine ────────────────────────────────────────────── */

/**
 * A clean scan currently has nothing to read, which is a marketing failure as
 * much as a UX one: the person most likely to share a report is the one who
 * just passed. These turn real passes into something worth showing.
 *
 * Every line is a restatement of a check that actually passed — never a claim
 * we did not test for.
 */
const CLEARED: Record<string, string> = {
  supabase: 'A stranger holding your public key could not read a single table.',
  firebase: 'Your Firestore and Realtime Database refused an anonymous reader.',
  secrets: 'No server key, token or password is sitting in the JavaScript you ship.',
  libs: 'None of the JavaScript libraries on your page match a published advisory.',
  ai: 'Your AI and MCP endpoints asked us to log in.',
  routes: 'Admin and debug routes refused us, including the ones named in your own bundle.',
  paths: 'Nothing sensitive is being served: no .env, no .git, no database dump.',
  headers: 'The headers that stop framing, sniffing and injected scripts are all set.',
  transport: 'HTTPS is enforced end to end and your domain is not open to takeover.',
  email: 'Nobody can send email that appears to come from your domain.',
  privacy: 'An EU visitor gets nothing tracked before they agree to it.',
  devserver: 'You are serving a real production build, not a dev server.',
  smuggling: 'No invisible text is hiding on your page for an AI to obey.',
  scaffold: 'Your app has its own name and description, not a generator default.',
  visibility: 'Search engines and AI answer engines can read and cite this page.',
  fundamentals: 'Title, description and viewport are all where a browser expects them.',
  accessibility: 'No automated accessibility barriers: every field, button and link we found can be named and reached.',
  lighthouse: 'Google measured this page as fast, accessible and correctly marked up.',
};

/** Plain-English lines for every category that came back clean. */
export function cleared(report: Report): string[] {
  return report.categories
    .filter((c) => c.grade === 'A' && c.checks.length > 0 && c.checks.every((k) => k.pass))
    .map((c) => CLEARED[c.key])
    .filter((line): line is string => Boolean(line));
}
