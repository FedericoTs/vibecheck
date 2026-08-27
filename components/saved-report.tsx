'use client';

import { useMemo, useState } from 'react';
import type { SavedReport } from '@/lib/report-store';
import type { Report } from '@/lib/scan/report';
import { severityCounts } from '@/lib/scan/report';
import { pillars, ranked, unknowns, cleared, verdict } from '@/lib/scan/insights';
import { fixFor } from '@/lib/scan/fixes';
import {
  SectionHead,
  ScanHeader,
  PillarScorecard,
  PriorityQueue,
  UnknownPanel,
  ClearedPanel,
  Contents,
} from '@/components/report-document';

/** en-GB, because a report read in Dublin should not say 8/27/2026. */
const fmt = (iso: string) =>
  new Date(iso).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' });

export function SavedReportView({ saved, retentionDays }: { saved: SavedReport; retentionDays: number }) {
  const [copied, setCopied] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [deleted, setDeleted] = useState(false);
  const [deleteError, setDeleteError] = useState('');

  // Rebuild the shape the document components already know how to render, so a
  // saved report and a live one cannot drift apart visually.
  const report: Report = useMemo(
    () => ({
      overallGrade: saved.grade,
      verdict: saved.verdict,
      issueCount: saved.issueCount,
      passed: saved.passed,
      total: saved.total,
      categories: saved.categories,
    }),
    [saved],
  );

  const pillarViews = useMemo(() => pillars(report), [report]);
  const queue = useMemo(() => ranked(report), [report]);
  const undetermined = useMemo(() => unknowns(report), [report]);
  const clearedLines = useMemo(() => cleared(report), [report]);
  const summary = useMemo(() => verdict(report), [report]);
  const sev = useMemo(() => severityCounts(report), [report]);

  const site = `https://${saved.host}`;

  // The social share points at the STATS card, never at this page. Posting a
  // full findings report to X would publish a working list of what is wrong
  // with a live site, which is the opposite of what a security tool should
  // cause to happen.
  const shareUrl =
    typeof window === 'undefined'
      ? ''
      : `${window.location.origin}/r?g=${report.overallGrade}&i=${report.issueCount}&p=${report.passed}&s=${saved.skipped.length}&t=${report.total}&c=${sev.critical}&h=${sev.high}`;

  const shareText = `${saved.host} scored ${report.overallGrade} on vibecheck — ${report.passed} checks passed, ${report.issueCount} to fix.`;

  const copyLink = async () => {
    await navigator.clipboard.writeText(window.location.href);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Revocation. Confirm first, because there is no undo and no second copy.
  const removeReport = async () => {
    if (!window.confirm('Delete this saved report? The link stops working immediately and this cannot be undone.')) return;
    setDeleting(true);
    setDeleteError('');
    try {
      const res = await fetch(`/api/report?slug=${encodeURIComponent(saved.slug)}`, { method: 'DELETE' });
      const data = await res.json();
      if (!res.ok) throw new Error(data?.error ?? 'Could not delete');
      setDeleted(true);
    } catch (e) {
      setDeleteError(e instanceof Error ? e.message : 'Could not delete that report');
    } finally {
      setDeleting(false);
    }
  };

  if (deleted) {
    return (
      <section className="border border-line bg-panel p-8">
        <p className="kicker mb-2">Deleted</p>
        <p className="font-display text-xl tracking-tight text-ink">This report is gone.</p>
        <p className="mt-2 max-w-2xl text-sm leading-relaxed text-muted">
          The link no longer works for anyone. Nothing about {saved.host} is stored any more. You can scan it again
          at any time.
        </p>
      </section>
    );
  }

  return (
    <section>
      <div className="mb-5">
        <ScanHeader
          host={saved.host}
          scannedAt={fmt(saved.savedAt)}
          total={report.total}
          catalogue={report.total}
          partial={saved.skipped.length}
        />
      </div>

      {/* The subject of the report, linked. Someone reading this should be one
          click away from the thing it describes. */}
      <div
        className={`border bg-panel lg:flex lg:items-stretch ${
          report.issueCount > 0 ? 'border-danger/40' : 'border-safe/40'
        }`}
      >
        <div className="min-w-0 flex-1 p-6">
          <p className="kicker mb-2">Saved report</p>
          <h1 className="font-display text-2xl font-semibold tracking-tight text-ink sm:text-3xl">
            <a href={site} rel="noopener" className="transition-colors hover:text-safe">
              {saved.host}
            </a>
          </h1>
          <p className="mt-3 max-w-2xl font-display text-lg leading-snug text-ink">{summary.headline}</p>
          {summary.weakest && (
            <p className="mt-2 max-w-2xl text-sm leading-relaxed text-muted">
              Strongest area <span className="text-ink">{summary.strongest}</span>. Weakest area{' '}
              <span className="text-ink">{summary.weakest}</span> — start there.
            </p>
          )}
        </div>

        <div className="flex divide-x divide-line border-t border-line lg:w-64 lg:shrink-0 lg:flex-col lg:divide-x-0 lg:divide-y lg:border-l lg:border-t-0">
          <div className="flex-1 px-5 py-3">
            <p className="font-mono text-lg font-semibold text-safe">{report.passed}</p>
            <p className="kicker text-faint">passed</p>
          </div>
          <div className="flex-1 px-5 py-3">
            <p className={`font-mono text-lg font-semibold ${report.issueCount > 0 ? 'text-danger' : 'text-muted'}`}>
              {report.issueCount}
            </p>
            <p className="kicker text-faint">to fix</p>
          </div>
          <div className="flex-1 px-5 py-3">
            <p className="font-mono text-lg font-semibold text-muted">{report.total}</p>
            <p className="kicker text-faint">checks run</p>
          </div>
        </div>
      </div>

      {/* Two share actions, labelled as two different things, because they carry
          very different amounts of information about a live site. */}
      <div className="mt-4 border border-line bg-panel p-5">
        <p className="kicker mb-3">Share this result</p>
        <div className="flex flex-wrap gap-2.5">
          <a
            href={`https://twitter.com/intent/tweet?text=${encodeURIComponent(shareText)}&url=${encodeURIComponent(shareUrl)}`}
            target="_blank"
            rel="noopener noreferrer"
            className="border border-line px-4 py-2 font-mono text-xs uppercase tracking-wider text-muted transition hover:border-ink hover:text-ink"
          >
            post the score
          </a>
          <a
            href={`https://www.linkedin.com/sharing/share-offsite/?url=${encodeURIComponent(shareUrl)}`}
            target="_blank"
            rel="noopener noreferrer"
            className="border border-line px-4 py-2 font-mono text-xs uppercase tracking-wider text-muted transition hover:border-ink hover:text-ink"
          >
            share on LinkedIn
          </a>
          <button
            onClick={copyLink}
            className="border border-ink bg-ink px-4 py-2 font-mono text-xs uppercase tracking-wider text-canvas transition hover:bg-transparent hover:text-ink"
          >
            {copied ? 'link copied' : 'copy the private link'}
          </button>
        </div>
        <p className="mt-3 max-w-3xl text-xs leading-relaxed text-faint">
          The social buttons share the <span className="text-muted">score card</span> — grade and counts only, no
          findings. The private link opens this full page, including the commands that prove each finding, so send it
          to your team rather than posting it. Anyone who has the link can read it.
        </p>
        <div className="mt-4 flex flex-wrap items-center gap-3 border-t border-line-soft pt-3">
          <button
            onClick={removeReport}
            disabled={deleting}
            className="font-mono text-[11px] uppercase tracking-wider text-faint transition hover:text-danger disabled:opacity-40"
          >
            {deleting ? 'deleting…' : 'delete this report'}
          </button>
          <span className="font-mono text-[11px] text-faint">
            or leave it — it deletes itself after {retentionDays} days
          </span>
          {deleteError && <span className="font-mono text-[11px] text-warn">{deleteError}</span>}
        </div>
      </div>

      <div className="mt-6">
        <Contents
          items={[
            { id: 'scorecard', label: 'Scorecard' },
            ...(queue.length > 0 ? [{ id: 'fix-first', label: 'Fix first', count: queue.length }] : []),
            ...(undetermined.length > 0 ? [{ id: 'unknown', label: 'Undetermined', count: undetermined.length }] : []),
            ...(clearedLines.length > 0 ? [{ id: 'cleared', label: 'Already fine' }] : []),
          ]}
        />
      </div>

      <div className="mt-8 space-y-4">
        <SectionHead
          id="scorecard"
          n="01 · Scorecard"
          title="Every area we measured"
          note="Security is the only pillar that sets the grade. The rest are reported beside it."
        />
        <PillarScorecard pillars={pillarViews} fixFor={fixFor} />
      </div>

      {queue.length > 0 && (
        <div className="mt-10 space-y-4">
          <SectionHead
            id="fix-first"
            n="02 · Fix first"
            title={queue.length === 1 ? 'One thing to fix' : `${queue.length} things to fix, worst first`}
            note={
              queue.length === report.issueCount
                ? 'Ordered by how much each one actually matters. Start at the top.'
                : `Ordered by how much each one actually matters. ${report.issueCount} of these set the grade; the rest are privacy, findability and performance, which are reported beside it and never counted against it.`
            }
          />
          <PriorityQueue findings={queue} fixFor={fixFor} />
        </div>
      )}

      {undetermined.length > 0 && (
        <div className="mt-10" id="unknown">
          <UnknownPanel items={undetermined} />
        </div>
      )}

      {clearedLines.length > 0 && (
        <div className="mt-10 space-y-4">
          <SectionHead
            id="cleared"
            n="03 · Already fine"
            title="What a stranger tried and could not get"
            note="Each line is a check that actually ran and passed."
          />
          <ClearedPanel lines={clearedLines} />
        </div>
      )}

      <p className="mt-10 border-t border-line pt-4 font-mono text-xs text-faint">
        Scanned {fmt(saved.savedAt)} · this report describes that moment and is deleted after {retentionDays} days ·{' '}
        <a href={site} rel="noopener" className="text-muted transition-colors hover:text-ink">
          {saved.host}
        </a>
      </p>
    </section>
  );
}
