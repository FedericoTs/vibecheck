import type { Grade } from '@/lib/scan/types';
import { SEVERITY_ORDER, severityCounts, type Report, type ReportCategory, type Severity } from '@/lib/scan/report';
import type { LighthouseScores, CoreWebVitals } from '@/lib/scan/lighthouse';
import type { CrawlerAccess } from '@/lib/scan/visibility';

/** grade -> letter/border colour classes, shared across the report. */
export function tone(grade: Grade | null): string {
  if (grade === 'A' || grade === 'B') return 'text-safe border-safe/40';
  if (grade === 'C') return 'text-warn border-warn/40';
  if (grade === 'D' || grade === 'F') return 'text-danger border-danger/50';
  return 'text-muted border-line';
}

const strokeForGrade = (g: Grade): string =>
  g === 'A' || g === 'B' ? 'stroke-safe' : g === 'C' ? 'stroke-warn' : 'stroke-danger';

/**
 * How "full" the grade ring reads. This is a QUALITATIVE gauge, not an invented
 * score: an A looks complete, an F looks depleted, so a bad grade looks bad at a
 * glance. The real, exact numbers live in the pass/fail metric row beside it.
 */
const GRADE_FILL: Record<Grade, number> = { A: 1, B: 0.82, C: 0.6, D: 0.4, F: 0.16 };

export const SEVERITY_STYLE: Record<Severity, { bar: string; text: string; label: string }> = {
  critical: { bar: 'bg-danger', text: 'text-danger', label: 'critical' },
  high: { bar: 'bg-danger/60', text: 'text-danger/80', label: 'high' },
  medium: { bar: 'bg-warn', text: 'text-warn', label: 'medium' },
  low: { bar: 'bg-muted/50', text: 'text-muted', label: 'low' },
};

/**
 * A proportional pass/fail bar. Pure CSS — no chart library, which keeps the
 * bundle small. It encodes the same numbers shown as text.
 */
export function PassBar({ passed, total, className = '' }: { passed: number; total: number; className?: string }) {
  if (total <= 0) return null;
  const pct = Math.round((passed / total) * 100);
  return (
    <div className={`flex h-1.5 w-full overflow-hidden bg-line ${className}`} role="img" aria-label={`${passed} of ${total} checks passed`}>
      <div className="bg-safe transition-all duration-700" style={{ width: `${pct}%` }} />
      <div className="bg-danger transition-all duration-700" style={{ width: `${100 - pct}%` }} />
    </div>
  );
}

/**
 * The grade gauge — the element people screenshot. The arc encodes the grade
 * band (A full, F nearly empty) in the grade's own colour, with the letter in
 * the centre. It invents no number: it is a visual restatement of the letter.
 */
export function ScoreDial({ grade, size = 128 }: { grade: Grade; size?: number }) {
  const stroke = 9;
  const r = (size - stroke) / 2;
  const circ = 2 * Math.PI * r;
  const fill = GRADE_FILL[grade] ?? 0.5;
  const letterTone = tone(grade).split(' ')[0];
  return (
    <div className="relative shrink-0" style={{ width: size, height: size }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" className="stroke-line" strokeWidth={stroke} />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          className={`${strokeForGrade(grade)} transition-all duration-1000 ease-out`}
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={circ}
          strokeDashoffset={circ * (1 - fill)}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className={`font-mono text-5xl font-semibold leading-none ${letterTone}`}>{grade}</span>
        <span className="kicker mt-1.5 text-[0.58rem]">grade</span>
      </div>
    </div>
  );
}

function severityRank(s: Severity | null): number {
  return s ? SEVERITY_ORDER.indexOf(s) : 99;
}

/** The worst severity among a category's FAILING checks (null if it's clean). */
function worstSeverity(c: ReportCategory): Severity | null {
  const fails = c.checks.filter((x) => !x.pass);
  if (fails.length === 0) return null;
  for (const s of SEVERITY_ORDER) if (fails.some((f) => f.severity === s)) return s;
  return 'low';
}

/**
 * Issues weighted by severity. Nine findings is not nine equal problems — one
 * anonymously-readable users table outweighs a missing Referrer-Policy. The bar
 * is proportional to the real counts; all four buckets are shown (empty ones
 * dimmed) so the shape of the damage reads at a glance.
 */
export function SeverityBar({ report }: { report: Report }) {
  const counts = severityCounts(report);
  const total = SEVERITY_ORDER.reduce((n, k) => n + counts[k], 0);
  if (total === 0) return null;
  const present = SEVERITY_ORDER.filter((k) => counts[k] > 0);
  return (
    <div className="border border-line bg-panel p-4">
      <div className="mb-3 flex items-baseline justify-between">
        <p className="kicker">Issues by severity</p>
        <p className="font-mono text-xs text-faint">{total} total</p>
      </div>
      <div className="flex h-2.5 w-full overflow-hidden bg-line">
        {present.map((k) => (
          <div key={k} className={SEVERITY_STYLE[k].bar} style={{ width: `${(counts[k] / total) * 100}%` }} title={`${counts[k]} ${SEVERITY_STYLE[k].label}`} />
        ))}
      </div>
      <div className="mt-3 grid grid-cols-4 gap-2">
        {SEVERITY_ORDER.map((k) => (
          <div key={k} className={`border px-2.5 py-1.5 ${counts[k] > 0 ? 'border-line' : 'border-line-soft opacity-40'}`}>
            <div className="flex items-center gap-1.5">
              <span className={`inline-block h-2 w-2 shrink-0 ${SEVERITY_STYLE[k].bar}`} />
              <span className={`font-mono text-base font-semibold ${counts[k] > 0 ? SEVERITY_STYLE[k].text : 'text-faint'}`}>{counts[k]}</span>
            </div>
            <span className="kicker mt-0.5 block text-[0.56rem]">{SEVERITY_STYLE[k].label}</span>
          </div>
        ))}
      </div>
      {counts.critical > 0 && (
        <p className="mt-3 text-xs leading-relaxed text-faint">
          Start with the {counts.critical} critical {counts.critical === 1 ? 'issue' : 'issues'} — those are the ones a stranger can act on right now.
        </p>
      )}
    </div>
  );
}

/**
 * Every category as a compact tile — the whole report on one screen. Failing
 * tiles sort first (and by worst severity), so the eye lands on what to fix
 * instead of reading a fixed order.
 */
export function CategoryMatrix({ categories }: { categories: ReportCategory[] }) {
  const sorted = [...categories].sort((a, b) => {
    const fa = a.checks.filter((x) => !x.pass).length;
    const fb = b.checks.filter((x) => !x.pass).length;
    if (fa > 0 !== fb > 0) return fa > 0 ? -1 : 1; // failing tiles first
    const sr = severityRank(worstSeverity(a)) - severityRank(worstSeverity(b));
    if (sr !== 0) return sr; // then by worst severity
    return fb - fa; // then by how many
  });
  return (
    <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
      {sorted.map((c) => {
        const fails = c.checks.filter((x) => !x.pass).length;
        const sev = worstSeverity(c);
        return (
          <div key={c.key} className={`border bg-panel px-3 py-2.5 ${fails > 0 ? 'border-danger/40' : 'border-line'}`}>
            <div className="flex items-start justify-between gap-2">
              <p className="font-mono text-[11px] uppercase leading-tight tracking-wide text-muted">{c.label}</p>
              <span className={`shrink-0 font-mono text-sm font-semibold ${tone(c.grade).split(' ')[0]}`}>{c.grade ?? '—'}</span>
            </div>
            <div className="mt-1 flex items-center gap-1.5">
              {sev && <span className={`inline-block h-1.5 w-1.5 shrink-0 rounded-full ${SEVERITY_STYLE[sev].bar}`} />}
              <p className={`font-mono text-[11px] ${fails > 0 ? 'text-danger' : 'text-faint'}`}>{fails > 0 ? `${fails} to fix` : 'all clear'}</p>
            </div>
            <PassBar passed={c.checks.length - fails} total={c.checks.length} className="mt-2" />
          </div>
        );
      })}
    </div>
  );
}

const LH_ITEMS: Array<[keyof LighthouseScores, string]> = [
  ['performance', 'Performance'],
  ['seo', 'SEO'],
  ['accessibility', 'Accessibility'],
  ['bestPractices', 'Best practices'],
];
// Static class names so Tailwind keeps them; dynamic `stroke-${x}` would be purged.
const LH_STROKE = { safe: 'stroke-safe', warn: 'stroke-warn', danger: 'stroke-danger' } as const;
const LH_TEXT = { safe: 'text-safe', warn: 'text-warn', danger: 'text-danger' } as const;
const lhTone = (s: number): 'safe' | 'warn' | 'danger' => (s >= 90 ? 'safe' : s >= 50 ? 'warn' : 'danger');

/**
 * PageSpeed-style score rings for the Lighthouse categories — the 0-100 gauge
 * people expect from web-quality tooling. Colour follows Google's bands
 * (0-49 red, 50-89 amber, 90-100 green). Reported, never in the security headline.
 */
export function LighthouseGauges({ scores }: { scores: LighthouseScores }) {
  const items = LH_ITEMS.map(([k, label]) => ({ label, score: scores[k] })).filter(
    (x): x is { label: string; score: number } => x.score != null,
  );
  if (items.length === 0) return null;
  const size = 96;
  const stroke = 8;
  const r = (size - stroke) / 2;
  const circ = 2 * Math.PI * r;
  return (
    <div className="grid grid-cols-2 gap-x-4 gap-y-6 sm:grid-cols-4">
      {items.map(({ label, score }) => {
        const tone = lhTone(score);
        return (
          <div key={label} className="flex flex-col items-center">
            <div className="relative" style={{ width: size, height: size }}>
              <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="-rotate-90">
                <circle cx={size / 2} cy={size / 2} r={r} fill="none" className="stroke-line" strokeWidth={stroke} />
                <circle
                  cx={size / 2}
                  cy={size / 2}
                  r={r}
                  fill="none"
                  className={`${LH_STROKE[tone]} transition-all duration-700 ease-out`}
                  strokeWidth={stroke}
                  strokeLinecap="round"
                  strokeDasharray={circ}
                  strokeDashoffset={circ * (1 - score / 100)}
                />
              </svg>
              <div className={`absolute inset-0 flex items-center justify-center font-mono text-xl font-semibold ${LH_TEXT[tone]}`}>
                {score}
              </div>
            </div>
            <p className="kicker mt-2.5 text-center">{label}</p>
          </div>
        );
      })}
    </div>
  );
}

const CWV_DOT = { good: 'bg-safe', 'needs-improvement': 'bg-warn', poor: 'bg-danger' } as const;
const CWV_TEXT = { good: 'text-safe', 'needs-improvement': 'text-warn', poor: 'text-danger' } as const;

/**
 * Core Web Vitals from the Chrome UX Report — REAL-user field data (trailing 28
 * days), not lab numbers, so it's what Google actually ranks on. Coloured by
 * Google's good / needs-improvement / poor thresholds.
 */
export function WebVitals({ cwv }: { cwv: CoreWebVitals }) {
  return (
    <div className="mt-6 border-t border-line pt-5">
      <p className="kicker mb-3">
        Core Web Vitals{' '}
        <span className="tracking-normal text-faint" style={{ textTransform: 'none' }}>
          · real users, last 28 days{cwv.origin ? ' · whole domain' : ''}
        </span>
      </p>
      <div className="grid grid-cols-3 gap-3">
        {cwv.metrics.map((m) => (
          <div key={m.label} className="border border-line bg-panel px-3 py-3">
            <div className="flex items-center gap-1.5">
              <span className={`inline-block h-2 w-2 shrink-0 rounded-full ${CWV_DOT[m.rating]}`} />
              <span className="kicker">{m.label}</span>
            </div>
            <p className={`mt-1.5 font-mono text-lg font-semibold ${CWV_TEXT[m.rating]}`}>{m.display}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

function CrawlerRow({ c }: { c: CrawlerAccess }) {
  return (
    <div className="flex items-center justify-between gap-3 border-b border-line-soft py-2 last:border-0">
      <div className="min-w-0">
        <div className="truncate font-mono text-xs text-ink">{c.name}</div>
        <div className="truncate font-mono text-[11px] text-faint">{c.purpose}</div>
      </div>
      {c.allowed ? (
        <span className="shrink-0 font-mono text-xs text-safe">✓ allowed</span>
      ) : (
        <span className="shrink-0 font-mono text-xs text-danger">✗ blocked</span>
      )}
    </div>
  );
}

/**
 * Which search engines and AI answer-engines robots.txt lets in. Blocking is a
 * legitimate choice, so this is REPORTED, never graded — but it's the single
 * thing that decides whether ChatGPT / Claude / Perplexity / Gemini can cite you.
 */
export function CrawlerMatrix({ crawlers }: { crawlers: CrawlerAccess[] }) {
  const search = crawlers.filter((c) => c.group === 'search');
  const ai = crawlers.filter((c) => c.group === 'ai');
  const blocked = crawlers.filter((c) => !c.allowed).length;
  return (
    <div className="border border-line bg-panel p-5">
      <div className="mb-4 flex items-baseline justify-between">
        <p className="kicker">
          Crawler access{' '}
          <span className="tracking-normal text-faint" style={{ textTransform: 'none' }}>
            · from robots.txt
          </span>
        </p>
        <p className="font-mono text-xs text-faint">{blocked === 0 ? 'all allowed' : `${blocked} blocked`}</p>
      </div>
      <div className="grid gap-x-8 gap-y-5 sm:grid-cols-2">
        <div>
          <p className="kicker mb-1">Search engines</p>
          {search.map((c) => (
            <CrawlerRow key={c.name} c={c} />
          ))}
        </div>
        <div>
          <p className="kicker mb-1">AI answer engines</p>
          {ai.map((c) => (
            <CrawlerRow key={c.name} c={c} />
          ))}
        </div>
      </div>
      <p className="mt-4 text-xs leading-relaxed text-faint">
        Blocking a crawler is a deliberate choice — reported, not graded. But if you want ChatGPT, Claude, Perplexity
        or Gemini to be able to cite you, those bots need access.
      </p>
    </div>
  );
}
