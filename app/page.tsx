'use client';

import { useState } from 'react';
import { scanSupabase } from '@/lib/scan/supabase';
import { combineReport, type Report } from '@/lib/scan/report';
import type { Grade } from '@/lib/scan/types';
import type { HeadersScanResult } from '@/lib/scan/headers';

const GITHUB_URL = 'https://github.com/FedericoTs/vibecheck';
const X_URL = 'https://x.com/FedericoTs'; // TODO: set the real handle before launch

function tone(grade: Grade | null): string {
  if (grade === 'A' || grade === 'B') return 'text-safe border-safe/40';
  if (grade === 'C') return 'text-warn border-warn/40';
  if (grade === 'D' || grade === 'F') return 'text-danger border-danger/50';
  return 'text-muted border-line';
}

export default function Home() {
  const [appUrl, setAppUrl] = useState('');
  const [showDb, setShowDb] = useState(false);
  const [sbUrl, setSbUrl] = useState('');
  const [anonKey, setAnonKey] = useState('');
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState<Report | null>(null);
  const [error, setError] = useState('');
  const [copied, setCopied] = useState(false);

  async function run(e: React.FormEvent) {
    e.preventDefault();
    setError('');
    if (!appUrl.trim() && !(sbUrl.trim() && anonKey.trim())) {
      setError('Enter your app URL, or add a Supabase project to check.');
      return;
    }
    setLoading(true);
    setReport(null);
    const headersP: Promise<HeadersScanResult | null> = appUrl.trim()
      ? fetch('/api/scan/headers', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ url: appUrl }),
        })
          .then((r) => r.json())
          .then((j) => (j?.error ? (setError(`Headers: ${j.error}`), null) : (j as HeadersScanResult)))
          .catch(() => (setError('Could not reach that app URL.'), null))
      : Promise.resolve(null);
    const sbP =
      sbUrl.trim() && anonKey.trim() ? scanSupabase({ url: sbUrl, anonKey }) : Promise.resolve(null);
    try {
      const [hdr, sb] = await Promise.all([headersP, sbP]);
      setReport(combineReport(sb, hdr));
    } finally {
      setLoading(false);
    }
  }

  function share() {
    const g = report?.overallGrade;
    const text = `I ran vibecheck on my app — grade ${g}${
      report?.issueCount ? `, ${report.issueCount} issue${report.issueCount === 1 ? '' : 's'} found` : ''
    }. Check yours: ${GITHUB_URL}`;
    navigator.clipboard?.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    });
  }

  function reset() {
    setReport(null);
    setError('');
  }

  return (
    <main className="mx-auto w-full max-w-2xl px-5 py-10 sm:py-16">
      {/* status bar */}
      <div className="mb-14 flex items-center justify-between kicker">
        <span>vibecheck ▸ security scan</span>
        <a href={GITHUB_URL} className="text-faint hover:text-ink transition-colors">
          open source ↗
        </a>
      </div>

      {!report && (
        <>
          <header className="mb-10">
            <p className="kicker mb-4">Security report card · for AI-built apps</p>
            <h1 className="font-display text-5xl sm:text-6xl font-semibold tracking-tight leading-[1.02]">
              Is your app
              <br />
              <span className="text-danger">leaking</span>
              <span className="cursor ml-1 h-[0.9em] align-baseline" aria-hidden />
            </h1>
            <p className="mt-6 max-w-md text-muted leading-relaxed">
              AI code generators ship the same holes over and over — tables anyone can read, missing
              headers. Point vibecheck at your app and see what a stranger already can. In seconds.
            </p>
          </header>

          <form onSubmit={run} className="border border-line bg-panel">
            <div className="border-b border-line p-4">
              <label className="kicker block mb-2">Your app URL</label>
              <input
                value={appUrl}
                onChange={(e) => setAppUrl(e.target.value)}
                placeholder="myapp.com"
                className="w-full bg-transparent font-mono text-sm text-ink placeholder-faint outline-none"
              />
            </div>

            {!showDb ? (
              <button
                type="button"
                onClick={() => setShowDb(true)}
                className="block w-full border-b border-line px-4 py-3 text-left font-mono text-xs text-muted hover:text-ink transition-colors"
              >
                + add Supabase project <span className="text-faint">— checks database exposure</span>
              </button>
            ) : (
              <div className="border-b border-line p-4 space-y-3">
                <div>
                  <label className="kicker block mb-2">Supabase URL</label>
                  <input
                    value={sbUrl}
                    onChange={(e) => setSbUrl(e.target.value)}
                    placeholder="https://xxxx.supabase.co"
                    className="w-full bg-transparent font-mono text-sm text-ink placeholder-faint outline-none"
                  />
                </div>
                <div>
                  <label className="kicker block mb-2">Anon (public) key</label>
                  <input
                    value={anonKey}
                    onChange={(e) => setAnonKey(e.target.value)}
                    placeholder="eyJhbGci…"
                    className="w-full bg-transparent font-mono text-xs text-ink placeholder-faint outline-none"
                  />
                </div>
              </div>
            )}

            <div className="flex items-center justify-between p-4">
              <span className="kicker text-faint">runs in your browser</span>
              <button
                type="submit"
                disabled={loading}
                className="border border-ink bg-ink px-5 py-2 font-mono text-xs font-medium uppercase tracking-wider text-canvas transition hover:bg-transparent hover:text-ink disabled:opacity-40"
              >
                {loading ? 'scanning…' : 'run scan →'}
              </button>
            </div>
          </form>

          {error && <p className="mt-4 font-mono text-xs text-danger">{error}</p>}

          <p className="mt-6 text-xs leading-relaxed text-faint">
            Your keys and data never leave your machine — the database check runs entirely in your
            browser, and vibecheck stores nothing. It only shows what any visitor can already reach.
          </p>
        </>
      )}

      {report && (
        <section>
          {/* overall grade */}
          <div className="flex items-stretch border border-line bg-panel">
            <div
              className={`flex w-28 shrink-0 items-center justify-center border-r text-7xl font-semibold font-mono ${tone(
                report.overallGrade,
              )}`}
            >
              {report.overallGrade}
            </div>
            <div className="flex flex-col justify-center p-5">
              <p className="kicker mb-1">Overall</p>
              <p className="font-display text-lg leading-snug">{report.verdict}</p>
              <p className="mt-1 font-mono text-xs text-muted">
                {report.issueCount === 0 ? 'no issues found' : `${report.issueCount} issue${report.issueCount === 1 ? '' : 's'} found`}
              </p>
            </div>
          </div>

          {/* categories */}
          <div className="mt-4 border border-line bg-panel divide-y divide-line">
            {report.categories.map((c, i) => (
              <div key={c.key} className="p-5">
                <div className="flex items-center justify-between">
                  <p className="kicker">
                    {String(i + 1).padStart(2, '0')} — {c.label}
                  </p>
                  <span className={`border px-2 py-0.5 font-mono text-xs ${tone(c.grade)}`}>
                    {c.grade ?? '—'}
                  </span>
                </div>
                <p className="mt-2 text-sm text-muted">{c.summary}</p>
                {c.findings.length > 0 && (
                  <ul className="mt-3 space-y-1.5 border-l border-danger/40 pl-3">
                    {c.findings.map((f, j) => (
                      <li key={j} className="font-mono text-xs text-ink/90">
                        <span className="text-danger">✗ </span>
                        {f}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            ))}
          </div>

          {error && <p className="mt-4 font-mono text-xs text-warn">{error}</p>}

          {/* tenant-guard funnel — only when there's an actual database exposure (its remit) */}
          {report.categories.some((c) => c.key === 'supabase' && c.findings.length > 0) && (
            <div className="mt-4 border border-line bg-panel p-5">
              <p className="kicker mb-2">Stop it shipping again</p>
              <p className="text-sm text-muted">
                Add a guard test to your CI so a cross-tenant leak fails the build before it merges:
              </p>
              <code className="mt-3 block border border-line bg-canvas px-3 py-2 font-mono text-xs text-safe">
                npx tenant-guard prove
              </code>
            </div>
          )}

          {/* actions — offers, never walls */}
          <div className="mt-6 flex flex-wrap items-center gap-3">
            <button onClick={reset} className="border border-line px-4 py-2 font-mono text-xs text-ink hover:border-ink transition-colors">
              ↺ scan another
            </button>
            <button onClick={share} className="border border-line px-4 py-2 font-mono text-xs text-ink hover:border-ink transition-colors">
              {copied ? '✓ copied' : 'share result'}
            </button>
            <a href={GITHUB_URL} className="border border-line px-4 py-2 font-mono text-xs text-ink hover:border-ink transition-colors">
              ★ star on GitHub
            </a>
            <a href={X_URL} className="border border-line px-4 py-2 font-mono text-xs text-ink hover:border-ink transition-colors">
              follow on X — if this helped
            </a>
          </div>
        </section>
      )}

      <footer className="mt-16 border-t border-line pt-5 kicker text-faint">
        free · open source · no signup · no telemetry · MIT
      </footer>
    </main>
  );
}
