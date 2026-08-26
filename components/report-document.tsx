/**
 * The report as a document.
 *
 * The old report was a grade followed by seventeen boxes that all looked the
 * same, so a readable database and a missing Referrer-Policy carried identical
 * visual weight and nothing told the reader where to start. These are the parts
 * that give it a spine: a provenance header, a verdict with real counts, pillar
 * scores drawn from numbers the scanners actually computed, a queue that says
 * what to do first, an honest list of what could not be determined, and a
 * summary of what is already fine.
 *
 * Two rules held throughout:
 *
 *   1. No invented numbers. Every bar is a score a scanner produced; every count
 *      counts real checks. Where there is no honest aggregate, nothing is drawn.
 *   2. Static class names only. Tailwind cannot see `text-${tone}`, so colour
 *      goes through the lookup maps below or it silently vanishes in production.
 */

import type { Grade } from '@/lib/scan/types';
import type { Severity, ReportCategory, CheckItem } from '@/lib/scan/report';
import type { PillarView, RankedFinding, Verdict } from '@/lib/scan/insights';

/* ── shared tone maps (static classes, see rule 2) ───────────────────── */

const GRADE_TEXT: Record<Grade, string> = {
  A: 'text-safe',
  B: 'text-safe',
  C: 'text-warn',
  D: 'text-danger',
  F: 'text-danger',
};

const GRADE_BORDER: Record<Grade, string> = {
  A: 'border-safe/40',
  B: 'border-safe/40',
  C: 'border-warn/40',
  D: 'border-danger/40',
  F: 'border-danger/40',
};

const SEVERITY_CHIP: Record<Severity, string> = {
  critical: 'border-danger/50 bg-danger/10 text-danger',
  high: 'border-danger/40 bg-danger/5 text-danger',
  medium: 'border-warn/40 bg-warn/10 text-warn',
  low: 'border-line bg-panel text-muted',
};

/** Score bands, matching scoreToGrade so the bar and the letter never disagree. */
function scoreTone(score: number): string {
  if (score >= 90) return 'bg-safe';
  if (score >= 75) return 'bg-safe/70';
  if (score >= 60) return 'bg-warn';
  return 'bg-danger';
}

/* ── section furniture ───────────────────────────────────────────────── */

/**
 * A real heading, with a numbered eyebrow above it.
 *
 * The old report had no h2 anywhere — every section title was the same 0.72rem
 * uppercase kicker as a caption, so there was no ladder to scan by. The numbers
 * are not decoration: this is a sequence a reader works through in order.
 */
export function SectionHead({
  n,
  title,
  note,
  id,
}: {
  n: string;
  title: string;
  note?: string;
  id?: string;
}) {
  return (
    <header id={id} className="scroll-mt-6">
      <p className="kicker">{n}</p>
      <h2 className="mt-1.5 font-display text-xl font-semibold tracking-tight text-ink sm:text-2xl">{title}</h2>
      {note && <p className="mt-2 max-w-2xl text-sm leading-relaxed text-muted">{note}</p>}
    </header>
  );
}

/* ── 1. provenance ───────────────────────────────────────────────────── */

/**
 * What was scanned, when, and how much of it ran.
 *
 * Naming the window inside the line beats a footnote: a reader should never
 * have to hunt for whether this is fresh or what "72 checks" was out of.
 */
export function ScanHeader({
  host,
  scannedAt,
  total,
  catalogue,
  partial,
}: {
  host: string;
  scannedAt: string;
  total: number;
  catalogue: number;
  partial?: number;
}) {
  return (
    <div className="flex flex-wrap items-baseline gap-x-4 gap-y-1 border-b border-line pb-4 font-mono text-xs text-faint">
      <span className="text-ink">{host}</span>
      <span>scanned {scannedAt}</span>
      <span>
        {total} of {catalogue} checks ran
      </span>
      {partial ? <span className="text-warn">{partial} could not run</span> : null}
    </div>
  );
}

/* ── 2. the verdict ──────────────────────────────────────────────────── */

/**
 * The headline, with the numbers behind it and a direction to read in.
 *
 * A letter tells someone how to feel. The counts tell them what was measured,
 * and strongest/weakest tells them which end to start at.
 */
export function VerdictBlock({ grade, verdict }: { grade: Grade; verdict: Verdict }) {
  return (
    <div className="space-y-2.5">
      <p className="font-display text-xl leading-snug tracking-tight text-ink sm:text-2xl">{verdict.headline}</p>
      {/* The counts live in the metric row beside this; repeating them here was
          one of the three overlapping summaries the old report opened with. What
          this adds is the part a number cannot give: where to start reading. */}
      {verdict.weakest && (
        <p className="text-sm leading-relaxed text-muted">
          Strongest area <span className="text-ink">{verdict.strongest}</span>. Weakest area{' '}
          <span className={GRADE_TEXT[grade]}>{verdict.weakest}</span> — start there.
        </p>
      )}
    </div>
  );
}

/* ── 3. the pillar scorecard ─────────────────────────────────────────── */

/**
 * One row per category, with the real 0-100 where the scanner computed one.
 *
 * Deliberately NOT a pillar average. Averaging eleven security categories would
 * let ten A's hide an F, which is the opposite of what a security report is for.
 * The pillar carries the worst grade in it — the same rule as the headline —
 * and each category shows its own honest number underneath.
 */
export function PillarScorecard({ pillars }: { pillars: PillarView[] }) {
  return (
    <div className="space-y-6">
      {pillars.map((p) => (
        <section key={p.group} className="border border-line bg-panel">
          <header className="flex items-start justify-between gap-4 border-b border-line-soft px-4 py-3">
            <div className="min-w-0">
              <h3 className="font-display text-sm font-semibold tracking-tight text-ink">{p.label}</h3>
              <p className="mt-1 text-xs leading-relaxed text-faint">{p.blurb}</p>
            </div>
            <div className="flex shrink-0 items-center gap-3">
              <span className="font-mono text-[11px] text-faint">
                {p.failing > 0 ? `${p.failing} to fix` : 'all clear'}
                {p.unknown > 0 ? ` · ${p.unknown} unknown` : ''}
              </span>
              {p.grade && (
                <span
                  className={`border px-2 py-0.5 font-mono text-xs font-semibold ${GRADE_BORDER[p.grade]} ${GRADE_TEXT[p.grade]}`}
                >
                  {p.grade}
                </span>
              )}
            </div>
          </header>

          <ul className="divide-y divide-line-soft">
            {p.categories.map((c) => (
              <CategoryScoreRow key={c.key} category={c} />
            ))}
          </ul>
        </section>
      ))}
    </div>
  );
}

/**
 * A category with a measured score gets a bar; one without gets a plain result.
 *
 * The binary categories are binary for a real reason — a dev build is being
 * served or it is not — and drawing them a 0 or 100 bar would dress a yes/no up
 * as a measurement.
 */
function CategoryScoreRow({ category }: { category: ReportCategory }) {
  const failing = category.checks.filter((c) => !c.pass && c.graded !== false).length;
  const scored = typeof category.score === 'number';

  return (
    <li className="flex items-center gap-4 px-4 py-2.5">
      <span className="min-w-0 flex-1 truncate text-sm text-muted">{category.label}</span>

      {scored ? (
        <>
          <span className="hidden h-1.5 w-32 shrink-0 bg-line sm:block" aria-hidden>
            <span className={`block h-full ${scoreTone(category.score!)}`} style={{ width: `${category.score}%` }} />
          </span>
          <span className="w-14 shrink-0 text-right font-mono text-xs tabular-nums text-faint">
            {category.score}
            <span className="text-line">/100</span>
          </span>
        </>
      ) : (
        <span className="w-14 shrink-0 text-right font-mono text-[11px] text-faint">
          {failing > 0 ? `${failing} to fix` : category.grade === null ? 'not run' : 'clear'}
        </span>
      )}

      <span
        className={`w-4 shrink-0 text-right font-mono text-xs ${
          category.grade ? GRADE_TEXT[category.grade] : 'text-faint'
        }`}
      >
        {category.grade ?? '—'}
      </span>
    </li>
  );
}

/* ── 4. the priority queue ───────────────────────────────────────────── */

/**
 * Every graded failure, worst first, numbered.
 *
 * This list already existed — failingChecks() has produced it for months — but
 * only the Markdown export and the fix prompt consumed it, so the download was
 * better organised than the page it came from. Putting it on screen is the
 * single biggest thing that stops the report reading as a checklist.
 */
export function PriorityQueue({
  findings,
  fixFor,
  limit,
}: {
  findings: RankedFinding[];
  fixFor: (categoryKey: string, check: CheckItem) => string;
  limit?: number;
}) {
  const shown = limit ? findings.slice(0, limit) : findings;
  const hidden = findings.length - shown.length;

  return (
    <div className="space-y-3">
      {shown.map((f) => (
        <FindingCard key={`${f.category.key}-${f.check.label}`} finding={f} fix={fixFor(f.category.key, f.check)} />
      ))}
      {hidden > 0 && (
        <p className="font-mono text-xs text-faint">
          + {hidden} more below, in the full audit.
        </p>
      )}
    </div>
  );
}

/**
 * One finding, always the same five blocks: what, where, proof, why it matters,
 * and what to do. Uniform anatomy is most of what makes a set of findings feel
 * like a document rather than a list of complaints.
 */
function FindingCard({ finding, fix }: { finding: RankedFinding; fix: string }) {
  const { check, category, severity, rank, action } = finding;

  return (
    <article className={`border bg-panel ${SEVERITY_CHIP[severity].split(' ')[0]}`}>
      <header className="flex items-start gap-3 border-b border-line-soft px-4 py-3">
        <span className="mt-0.5 font-mono text-xs tabular-nums text-faint">{String(rank).padStart(2, '0')}</span>
        <div className="min-w-0 flex-1">
          <h3 className="font-display text-sm font-medium leading-snug text-ink">{check.label}</h3>
          <p className="mt-1 font-mono text-[11px] uppercase tracking-wider text-faint">{category.label}</p>
        </div>
        <span className={`shrink-0 border px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider ${SEVERITY_CHIP[severity]}`}>
          {severity}
        </span>
      </header>

      <div className="space-y-3 px-4 py-3">
        {check.detail && <p className="font-mono text-xs leading-relaxed text-muted">{check.detail}</p>}

        {check.evidence && (
          <div>
            <pre className="overflow-x-auto border border-line bg-canvas px-3 py-2 font-mono text-xs text-safe">
              {check.evidence.command}
            </pre>
            <p className="mt-1 text-[11px] text-faint">{check.evidence.label}</p>
          </div>
        )}

        <p className="text-sm leading-relaxed text-muted">
          <span className="font-mono text-[11px] uppercase tracking-wider text-warn">Fix</span>{' '}
          {fix}
        </p>

        <p className="font-mono text-[11px] text-faint">Priority {rank} — {action}.</p>
      </div>
    </article>
  );
}

/* ── 5. what we could not determine ──────────────────────────────────── */

/**
 * The third state, given its own section instead of an amber tag buried in a
 * list of failures.
 *
 * A scanner that says plainly what it could not work out is trusted more on
 * what it did work out. Mixing these in with real failures loses that twice:
 * it reads as an accusation to the owner and as noise to everyone else.
 */
export function UnknownPanel({ items }: { items: { category: ReportCategory; check: CheckItem }[] }) {
  if (items.length === 0) return null;

  return (
    <div className="border border-warn/30 bg-panel">
      <header className="border-b border-line-soft px-4 py-3">
        <h3 className="font-display text-sm font-semibold tracking-tight text-warn">
          {items.length === 1 ? '1 check could not be determined' : `${items.length} checks could not be determined`}
        </h3>
        <p className="mt-1 text-xs leading-relaxed text-muted">
          Shown, but not counted against you in either direction. Not checked is not the same as clean.
        </p>
      </header>
      <ul className="divide-y divide-line-soft">
        {items.map(({ category, check }) => (
          <li key={`${category.key}-${check.label}`} className="px-4 py-2.5">
            <p className="text-sm text-ink">{check.label}</p>
            <p className="mt-0.5 font-mono text-[11px] text-faint">
              {category.label}
              {check.detail ? ` — ${check.detail}` : ''}
            </p>
          </li>
        ))}
      </ul>
    </div>
  );
}

/* ── 6. what is already fine ─────────────────────────────────────────── */

/**
 * A clean scan used to have nothing to read, which is a marketing problem as
 * much as a UX one: the person most likely to share a report is the one who
 * just passed it. Every line here restates a check that genuinely passed.
 */
export function ClearedPanel({ lines }: { lines: string[] }) {
  if (lines.length === 0) return null;

  return (
    <ul className="grid gap-x-6 gap-y-2 sm:grid-cols-2">
      {lines.map((line) => (
        <li key={line} className="flex gap-2.5 text-sm leading-relaxed text-muted">
          <span className="mt-px font-mono text-sm text-safe" aria-hidden>
            ✓
          </span>
          <span>{line}</span>
        </li>
      ))}
    </ul>
  );
}

/* ── 7. contents ─────────────────────────────────────────────────────── */

/** Jump links, so a ~78-check document is navigable instead of a long scroll. */
export function Contents({ items }: { items: { id: string; label: string; count?: number }[] }) {
  return (
    <nav aria-label="Report contents" className="flex flex-wrap gap-x-4 gap-y-2 border-y border-line py-3">
      {items.map((i) => (
        <a
          key={i.id}
          href={`#${i.id}`}
          className="font-mono text-[11px] uppercase tracking-wider text-faint transition hover:text-ink"
        >
          {i.label}
          {typeof i.count === 'number' && <span className="ml-1 text-line">{i.count}</span>}
        </a>
      ))}
    </nav>
  );
}
