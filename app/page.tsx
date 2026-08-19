'use client';

import { useState, useMemo } from 'react';
import { scanSupabase } from '@/lib/scan/supabase';
import { scanFirebase, type FirebaseConfig } from '@/lib/scan/firebase';
import { combineReport, type ReportInputs, type ReportCategory } from '@/lib/scan/report';
import { buildFixPrompt, fixFor } from '@/lib/scan/fixes';
import type { Grade } from '@/lib/scan/types';
import type { HeadersScanResult } from '@/lib/scan/headers';
import type { PathsScanResult } from '@/lib/scan/paths';
import type { RoutesScanResult } from '@/lib/scan/routes';
import type { AiSurfaceResult } from '@/lib/scan/ai-surface';
import type { PrivacyResult } from '@/lib/scan/privacy';
import type { EmailAuthResult } from '@/lib/scan/email-auth';
import type { SecretsScanResult } from '@/lib/scan/secrets';
import type { FundamentalsResult } from '@/lib/scan/fundamentals';
import type { LighthouseResult } from '@/lib/scan/lighthouse';

const GITHUB_URL = 'https://github.com/FedericoTs/vibecheck';
const X_URL = 'https://x.com/federico_sciuca';

function tone(grade: Grade | null): string {
  if (grade === 'A' || grade === 'B') return 'text-safe border-safe/40';
  if (grade === 'C') return 'text-warn border-warn/40';
  if (grade === 'D' || grade === 'F') return 'text-danger border-danger/50';
  return 'text-muted border-line';
}

function CategoryList({ categories }: { categories: ReportCategory[] }) {
  return (
    <div className="space-y-3">
      {categories.map((c) => (
        <div key={c.key} className="border border-line bg-panel">
          <div className="flex items-center justify-between border-b border-line px-4 py-2.5">
            <p className="font-mono text-xs font-medium uppercase tracking-wider text-ink">{c.label}</p>
            <span className={`border px-2 py-0.5 font-mono text-xs ${tone(c.grade)}`}>{c.grade ?? '—'}</span>
          </div>
          {c.checks.length > 0 ? (
            <ul className="divide-y divide-line-soft">
              {c.checks.map((ck, i) => (
                <li key={i} className="flex items-start gap-2.5 px-4 py-2.5">
                  <span className={`mt-px font-mono text-sm ${ck.pass ? 'text-safe' : 'text-danger'}`}>{ck.pass ? '✓' : '✗'}</span>
                  <div className="min-w-0 flex-1">
                    <span className={`text-sm ${ck.pass ? 'text-muted' : 'text-ink'}`}>{ck.label}</span>
                    {ck.detail && <span className="mt-0.5 block break-words font-mono text-xs text-faint">{ck.detail}</span>}
                    {!ck.pass && (
                      <span className="mt-1.5 block border-l border-warn/40 pl-2.5 text-xs leading-relaxed text-muted">
                        <span className="text-warn">Fix: </span>
                        {fixFor(c.key, ck)}
                      </span>
                    )}
                  </div>
                </li>
              ))}
            </ul>
          ) : (
            <p className="px-4 py-3 text-sm text-muted">{c.summary}</p>
          )}
        </div>
      ))}
    </div>
  );
}

export default function Home() {
  const [appUrl, setAppUrl] = useState('');
  const [showDb, setShowDb] = useState(false);
  const [sbUrl, setSbUrl] = useState('');
  const [anonKey, setAnonKey] = useState('');
  const [loading, setLoading] = useState(false);
  const [inputs, setInputs] = useState<ReportInputs | null>(null);
  const [lhLoading, setLhLoading] = useState(false);
  const [error, setError] = useState('');
  const [copied, setCopied] = useState(false);
  const [fixCopied, setFixCopied] = useState(false);
  const [badgeCopied, setBadgeCopied] = useState(false);
  const [autoDetected, setAutoDetected] = useState(false);
  const report = useMemo(() => (inputs ? combineReport(inputs) : null), [inputs]);

  async function run(e: React.FormEvent) {
    e.preventDefault();
    setError('');
    if (!appUrl.trim() && !(sbUrl.trim() && anonKey.trim())) {
      setError('Enter your app URL, or add a Supabase project to check.');
      return;
    }
    setLoading(true);
    setInputs(null);
    setLhLoading(false);
    setAutoDetected(false);
    const postScan = <T,>(endpoint: string): Promise<T | null> =>
      fetch(endpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ url: appUrl }),
      })
        .then((r) => r.json())
        .then((j) => (j?.error ? null : (j as T)))
        .catch(() => null);

    const headersP = appUrl.trim() ? postScan<HeadersScanResult>('/api/scan/headers') : Promise.resolve(null);
    const pathsP = appUrl.trim() ? postScan<PathsScanResult>('/api/scan/paths') : Promise.resolve(null);
    const secretsP = appUrl.trim()
      ? postScan<
          SecretsScanResult & {
            discovered?: { url: string; anonKey: string } | null;
            firebase?: FirebaseConfig | null;
            firebaseCollections?: string[];
          }
        >('/api/scan/secrets')
      : Promise.resolve(null);
    const fundamentalsP = appUrl.trim() ? postScan<FundamentalsResult>('/api/scan/fundamentals') : Promise.resolve(null);
    const routesP = appUrl.trim() ? postScan<RoutesScanResult>('/api/scan/routes') : Promise.resolve(null);
    const aiP = appUrl.trim() ? postScan<AiSurfaceResult>('/api/scan/ai') : Promise.resolve(null);
    const privacyP = appUrl.trim() ? postScan<PrivacyResult>('/api/scan/privacy') : Promise.resolve(null);
    const emailP = appUrl.trim() ? postScan<EmailAuthResult>('/api/scan/email') : Promise.resolve(null);
    try {
      const [hdr, paths, secrets, fundamentals, routes, ai, privacy, email] = await Promise.all([headersP, pathsP, secretsP, fundamentalsP, routesP, aiP, privacyP, emailP]);
      if (appUrl.trim() && !hdr && !paths && !secrets && !fundamentals) {
        setError('Could not reach that app URL — is it live and public?');
      }

      // Database check: use whatever the user typed, else the Supabase project the
      // app already exposes in its own bundle. Either way the probes run HERE, in
      // the browser — vibecheck's servers never query anyone's database.
      const creds =
        sbUrl.trim() && anonKey.trim()
          ? { url: sbUrl, anonKey }
          : secrets?.discovered ?? null;
      if (creds) setAutoDetected(!(sbUrl.trim() && anonKey.trim()));

      // Supabase and Firebase both probe from HERE, in the browser.
      const [sb, fb] = await Promise.all([
        creds ? scanSupabase(creds) : Promise.resolve(null),
        secrets?.firebase
          ? scanFirebase({ config: secrets.firebase, collections: secrets.firebaseCollections }).catch(() => null)
          : Promise.resolve(null),
      ]);
      if (secrets?.firebase) setAutoDetected(true);

      const base: ReportInputs = { supabase: sb, firebase: fb, headers: hdr, paths, routes, ai, secrets, fundamentals, privacy, email };
      setInputs(base);

      // Lighthouse is slow (10-30s) — render the security card now, fill it in when
      // ready. GET so Vercel's edge caches each URL's result (protects the PSI quota).
      if (appUrl.trim()) {
        setLhLoading(true);
        fetch(`/api/scan/lighthouse?url=${encodeURIComponent(appUrl)}`)
          .then((r) => r.json())
          .then((j) => (j?.error ? null : (j as LighthouseResult)))
          .catch(() => null)
          .then((lh) => {
            if (lh) setInputs((prev) => ({ ...(prev ?? base), lighthouse: lh }));
          })
          .finally(() => setLhLoading(false));
      }
    } finally {
      setLoading(false);
    }
  }

  function share() {
    if (!report) return;
    // A shareable link that unfurls into the OG card — grade + issue count only,
    // never the host, key, or findings.
    const url = `${window.location.origin}/r?g=${report.overallGrade}&i=${report.issueCount}`;
    navigator.clipboard?.writeText(url).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    });
  }

  function copyFixPrompt() {
    if (!report) return;
    // Deterministic prompt — no LLM, so it costs nothing and can't hallucinate a wrong fix.
    navigator.clipboard?.writeText(buildFixPrompt(report, appUrl.trim() || undefined)).then(() => {
      setFixCopied(true);
      setTimeout(() => setFixCopied(false), 2400);
    });
  }

  function copyBadge() {
    if (!report) return;
    const origin = window.location.origin;
    const md = `[![vibecheck security: ${report.overallGrade}](${origin}/badge?g=${report.overallGrade})](${origin})`;
    navigator.clipboard?.writeText(md).then(() => {
      setBadgeCopied(true);
      setTimeout(() => setBadgeCopied(false), 2400);
    });
  }

  function reset() {
    setInputs(null);
    setError('');
    setLhLoading(false);
  }

  return (
    <main className="mx-auto w-full max-w-2xl px-5 py-10 sm:py-16">
      {/* status bar */}
      <div className="mb-14 flex items-center justify-between kicker">
        <span>vibecheck ▸ security scan</span>
        <a href={GITHUB_URL} className="-my-2 py-2 text-faint transition-colors hover:text-ink">
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
                className="w-full bg-transparent font-mono text-base text-ink placeholder-faint outline-none sm:text-sm"
              />
            </div>

            {!showDb ? (
              <button
                type="button"
                onClick={() => setShowDb(true)}
                className="block w-full border-b border-line px-4 py-3 text-left font-mono text-xs text-muted hover:text-ink transition-colors"
              >
                + Supabase project <span className="text-faint">— optional; Supabase &amp; Firebase are auto-detected</span>
              </button>
            ) : (
              <div className="border-b border-line p-4 space-y-3">
                <div>
                  <label className="kicker block mb-2">Supabase URL</label>
                  <input
                    value={sbUrl}
                    onChange={(e) => setSbUrl(e.target.value)}
                    placeholder="https://xxxx.supabase.co"
                    className="w-full bg-transparent font-mono text-base text-ink placeholder-faint outline-none sm:text-sm"
                  />
                </div>
                <div>
                  <label className="kicker block mb-2">Anon (public) key</label>
                  <input
                    value={anonKey}
                    onChange={(e) => setAnonKey(e.target.value)}
                    placeholder="eyJhbGci…"
                    className="w-full bg-transparent font-mono text-base text-ink placeholder-faint outline-none sm:text-xs"
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
            Every other scanner queries your database from <em>their</em> servers. vibecheck runs the
            database probes in <span className="text-muted">your own browser</span> — we never query
            it, and we store nothing. It only ever reads what any visitor can already reach.
          </p>
        </>
      )}

      {report && (
        <section>
          {/* overall grade + how much was checked */}
          <div className="flex items-stretch border border-line bg-panel">
            <div className={`flex w-28 shrink-0 items-center justify-center border-r text-7xl font-semibold font-mono ${tone(report.overallGrade)}`}>
              {report.overallGrade}
            </div>
            <div className="flex flex-col justify-center p-5">
              <p className="kicker mb-1">Security grade</p>
              <p className="font-display text-lg leading-snug">{report.verdict}</p>
              <p className="mt-2 font-mono text-xs text-muted">
                <span className="text-safe">{report.passed}</span>/{report.total} checks passed
                {report.issueCount > 0 && (
                  <span className="text-danger"> · {report.issueCount} security issue{report.issueCount === 1 ? '' : 's'}</span>
                )}
              </p>
            </div>
          </div>

          {autoDetected && (
            <p className="mt-3 font-mono text-xs text-muted">
              <span className="text-safe">✓</span> Found your backend in the app&apos;s own bundle and probed
              it <span className="text-ink">from your browser</span> — nothing was sent to our servers.
            </p>
          )}

          {/* security categories — the headline */}
          <div className="mt-4">
            <CategoryList categories={report.categories.filter((c) => c.group === 'security')} />
          </div>

          {error && <p className="mt-4 font-mono text-xs text-warn">{error}</p>}

          {/* tenant-guard funnel — only when there's an actual database exposure */}
          {report.categories.some((c) => c.key === 'supabase' && c.checks.some((k) => !k.pass)) && (
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

          {/* EU privacy — its own grade, deliberately not part of the security headline */}
          {report.categories.some((c) => c.group === 'privacy') && (
            <div className="mt-8">
              <p className="kicker mb-3">
                EU privacy <span className="text-faint">· what an EU visitor gets before clicking anything</span>
              </p>
              <CategoryList categories={report.categories.filter((c) => c.group === 'privacy')} />
              <p className="mt-2 text-xs leading-relaxed text-faint">
                These are observations, not legal advice — whether they matter depends on your users and your legal basis.
              </p>
            </div>
          )}

          {/* fundamentals + performance — secondary, own grades */}
          {(report.categories.some((c) => c.group === 'basics' || c.group === 'performance') || lhLoading) && (
            <div className="mt-8">
              <p className="kicker mb-3">
                Fundamentals &amp; performance <span className="text-faint">· separate from the security grade</span>
              </p>
              <div className="space-y-3">
                {report.categories.some((c) => c.group === 'basics' || c.group === 'performance') && (
                  <CategoryList categories={report.categories.filter((c) => c.group === 'basics' || c.group === 'performance')} />
                )}
                {lhLoading && (
                  <div className="flex items-center gap-2.5 border border-line bg-panel px-4 py-3">
                    <span className="inline-block h-2 w-2 shrink-0 animate-pulse rounded-full bg-warn" />
                    <p className="font-mono text-xs text-muted">
                      Running Lighthouse — performance, SEO, accessibility{' '}
                      <span className="text-faint">(can take 10–30s)</span>
                    </p>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* earn-it badge: only offered on a clean security result */}
          {report.issueCount === 0 && (
            <div className="mt-8 border border-safe/30 bg-panel p-5">
              <p className="kicker mb-2 text-safe">Clean scan — show it off</p>
              <p className="text-sm text-muted">
                Add this to your README or footer. It links back here so anyone can run their own scan.
              </p>
              <div className="mt-3 flex items-center gap-3">
                {/* eslint-disable-next-line @next/next/no-img-element */}
                <img src={`/badge?g=${report.overallGrade}`} alt={`vibecheck security: ${report.overallGrade}`} width={126} height={20} />
                <button
                  onClick={copyBadge}
                  className="border border-line px-3 py-1.5 font-mono text-xs text-muted transition-colors hover:border-ink hover:text-ink"
                >
                  {badgeCopied ? '✓ markdown copied' : 'copy markdown'}
                </button>
              </div>
            </div>
          )}

          {/* actions — fixing comes first when there's something to fix */}
          <div className="mt-8 space-y-3">
            {report.issueCount > 0 && (
              <button
                onClick={copyFixPrompt}
                className="w-full border border-warn bg-warn/10 px-5 py-3 font-mono text-xs font-medium uppercase tracking-wider text-warn transition hover:bg-warn/20"
              >
                {fixCopied
                  ? '✓ copied — paste it into Lovable, Cursor, v0 or Claude'
                  : `⚡ copy the fix prompt (${report.issueCount} issue${report.issueCount === 1 ? '' : 's'})`}
              </button>
            )}
            <button
              onClick={share}
              className="w-full border border-ink bg-ink px-5 py-3 font-mono text-xs font-medium uppercase tracking-wider text-canvas transition hover:bg-transparent hover:text-ink"
            >
              {copied ? '✓ link copied — paste it anywhere' : 'share your result →'}
            </button>
            <a
              href={X_URL}
              target="_blank"
              rel="noreferrer"
              className="flex w-full items-center justify-center gap-2 border border-ink/50 bg-ink/5 px-5 py-3 font-mono text-xs text-ink transition hover:bg-ink/10"
            >
              <span className="text-sm font-semibold">𝕏</span> Follow @federico_sciuca — I built this, shipping more
            </a>
            <div className="flex flex-wrap gap-3 pt-1">
              <button onClick={reset} className="border border-line px-4 py-2 font-mono text-xs text-muted transition-colors hover:border-ink hover:text-ink">
                ↺ scan another
              </button>
              <a href={GITHUB_URL} className="border border-line px-4 py-2 font-mono text-xs text-muted transition-colors hover:border-ink hover:text-ink">
                ★ star on GitHub
              </a>
            </div>
          </div>
        </section>
      )}

      <footer className="mt-16 border-t border-line pt-6">
        <p className="kicker mb-3">More free, open-source tools by @federico_sciuca</p>
        <div className="flex flex-col gap-2 font-mono text-xs">
          <a href="https://github.com/FedericoTs/tenant-guard" className="py-1.5 text-muted transition-colors hover:text-ink">
            tenant-guard <span className="text-faint">— CI guard tests that catch multi-tenant leaks before they ship ↗</span>
          </a>
          <a href="https://github.com/FedericoTs/regulatory-crosswalk-provenance" className="py-1.5 text-muted transition-colors hover:text-ink">
            regulatory-crosswalk <span className="text-faint">— open dataset mapping NIS2 / DORA / ISO 27001 ↗</span>
          </a>
        </div>
        <p className="mt-5 kicker text-faint">
          free · open source · no signup · MIT ·{' '}
          <a href={X_URL} className="-my-1 inline-block py-1 transition-colors hover:text-ink">
            @federico_sciuca
          </a>
        </p>
      </footer>
    </main>
  );
}
