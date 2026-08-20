'use client';

import { useState, useMemo } from 'react';
import { scanSupabase } from '@/lib/scan/supabase';
import { scanFirebase, type FirebaseConfig } from '@/lib/scan/firebase';
import { combineReport, severityCounts, SEVERITY_ORDER, type ReportInputs, type ReportCategory, type CheckItem, type Report, type Severity } from '@/lib/scan/report';
import { buildFixPrompt, fixFor } from '@/lib/scan/fixes';
import type { Grade } from '@/lib/scan/types';
import type { HeadersScanResult } from '@/lib/scan/headers';
import type { PathsScanResult } from '@/lib/scan/paths';
import type { RoutesScanResult } from '@/lib/scan/routes';
import type { AiSurfaceResult } from '@/lib/scan/ai-surface';
import type { PrivacyResult } from '@/lib/scan/privacy';
import type { EmailAuthResult } from '@/lib/scan/email-auth';
import type { TransportResult } from '@/lib/scan/transport';
import type { VisibilityResult } from '@/lib/scan/visibility';
import type { RepoScanResult, RepoFinding } from '@/lib/scan/repo';
import { toCycloneDX } from '@/lib/scan/sbom';
import type { SecretsScanResult } from '@/lib/scan/secrets';
import type { FundamentalsResult } from '@/lib/scan/fundamentals';
import type { LighthouseResult } from '@/lib/scan/lighthouse';

const GITHUB_URL = 'https://github.com/FedericoTs/vibecheck';
const X_URL = 'https://x.com/federico_sciuca';
// Monitoring waitlist stays built but hidden until it is switched on.
// Flip NEXT_PUBLIC_WAITLIST=on in Vercel (and set the Resend vars) to show it.
const WAITLIST_ENABLED = process.env.NEXT_PUBLIC_WAITLIST === 'on';

/** Shown live while scanning, ticked off as each check returns. */
const SCAN_STEPS = [
  'secrets',
  'admin & debug routes',
  'AI & MCP endpoints',
  'exposed files',
  'security headers',
  'HTTPS & redirects',
  'email spoofing',
  'EU privacy',
  'AI & search visibility',
  'fundamentals',
];

function tone(grade: Grade | null): string {
  if (grade === 'A' || grade === 'B') return 'text-safe border-safe/40';
  if (grade === 'C') return 'text-warn border-warn/40';
  if (grade === 'D' || grade === 'F') return 'text-danger border-danger/50';
  return 'text-muted border-line';
}

const SEVERITY_STYLE: Record<Severity, { bar: string; text: string; label: string }> = {
  critical: { bar: 'bg-danger', text: 'text-danger', label: 'critical' },
  high: { bar: 'bg-danger/60', text: 'text-danger/80', label: 'high' },
  medium: { bar: 'bg-warn', text: 'text-warn', label: 'medium' },
  low: { bar: 'bg-muted/50', text: 'text-muted', label: 'low' },
};

/**
 * Issues weighted by severity. Nine findings is not nine equal problems — one
 * anonymously-readable users table outweighs a missing Referrer-Policy, and a
 * flat count hides exactly that. Widths are proportional to the real counts.
 */
function SeverityBreakdown({ report }: { report: Report }) {
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
          <div
            key={k}
            className={SEVERITY_STYLE[k].bar}
            style={{ width: `${(counts[k] / total) * 100}%` }}
            title={`${counts[k]} ${SEVERITY_STYLE[k].label}`}
          />
        ))}
      </div>
      <div className="mt-3 flex flex-wrap gap-x-5 gap-y-1.5">
        {present.map((k) => (
          <div key={k} className="flex items-center gap-2">
            <span className={`inline-block h-2 w-2 shrink-0 ${SEVERITY_STYLE[k].bar}`} />
            <span className="font-mono text-xs">
              <span className={`font-semibold ${SEVERITY_STYLE[k].text}`}>{counts[k]}</span>{' '}
              <span className="text-muted">{SEVERITY_STYLE[k].label}</span>
            </span>
          </div>
        ))}
      </div>
      {counts.critical > 0 && (
        <p className="mt-3 text-xs leading-relaxed text-faint">
          Start with the {counts.critical} critical {counts.critical === 1 ? 'issue' : 'issues'} — those are
          the ones a stranger can act on right now.
        </p>
      )}
    </div>
  );
}

/**
 * A proportional pass/fail bar. Pure CSS — no chart library, which keeps the
 * bundle small and matches the rest of the type. It encodes the same numbers
 * shown as text, so it adds a read-at-a-glance layer without inventing data.
 */
function PassBar({ passed, total, className = '' }: { passed: number; total: number; className?: string }) {
  if (total <= 0) return null;
  const pct = Math.round((passed / total) * 100);
  return (
    <div className={`flex h-1.5 w-full overflow-hidden bg-line ${className}`} role="img" aria-label={`${passed} of ${total} checks passed`}>
      <div className="bg-safe transition-all duration-500" style={{ width: `${pct}%` }} />
      <div className="bg-danger transition-all duration-500" style={{ width: `${100 - pct}%` }} />
    </div>
  );
}

/** One ✓/✗ row, with its fix inline when it failed. */
function CheckRow({ c, categoryKey }: { c: CheckItem; categoryKey: string }) {
  return (
    <li className="flex items-start gap-2.5 px-4 py-2.5">
      <span className={`mt-px font-mono text-sm ${c.pass ? 'text-safe' : 'text-danger'}`}>{c.pass ? '✓' : '✗'}</span>
      <div className="min-w-0 flex-1">
        <span className={`text-sm ${c.pass ? 'text-muted' : 'text-ink'}`}>{c.label}</span>
        {c.detail && <span className="mt-0.5 block break-words font-mono text-xs text-faint">{c.detail}</span>}
        {!c.pass && (
          <span className="mt-1.5 block border-l border-warn/40 pl-2.5 text-xs leading-relaxed text-muted">
            <span className="text-warn">Fix: </span>
            {fixFor(categoryKey, c)}
          </span>
        )}
      </div>
    </li>
  );
}

/**
 * A category card. Failures are always visible; passing checks collapse behind a
 * count — with ~78 checks, showing everything buries the handful that matter,
 * but hiding the count entirely would lose the proof of how much was examined.
 */
function CategoryCard({ c }: { c: ReportCategory }) {
  const failures = c.checks.filter((x) => !x.pass);
  const passes = c.checks.filter((x) => x.pass);
  const [showPasses, setShowPasses] = useState(false);

  return (
    <div className={`border bg-panel ${failures.length > 0 ? 'border-danger/30' : 'border-line'}`}>
      <div className="flex items-center justify-between border-b border-line px-4 py-2.5">
        <p className="font-mono text-xs font-medium uppercase tracking-wider text-ink">{c.label}</p>
        <span className={`border px-2 py-0.5 font-mono text-xs ${tone(c.grade)}`}>{c.grade ?? '—'}</span>
      </div>

      {c.checks.length === 0 ? (
        <p className="px-4 py-3 text-sm text-muted">{c.summary}</p>
      ) : (
        <>
          {failures.length > 0 && (
            <ul className="divide-y divide-line-soft">
              {failures.map((ck, i) => (
                <CheckRow key={i} c={ck} categoryKey={c.key} />
              ))}
            </ul>
          )}
          {passes.length > 0 && (
            <>
              <button
                onClick={() => setShowPasses((v) => !v)}
                className={`flex w-full items-center justify-between px-4 py-2.5 text-left font-mono text-xs text-muted transition-colors hover:text-ink ${
                  failures.length > 0 ? 'border-t border-line' : ''
                }`}
              >
                <span>
                  <span className="text-safe">✓</span> {passes.length} check{passes.length === 1 ? '' : 's'} passed
                </span>
                <span className="text-faint">{showPasses ? 'hide' : 'show'}</span>
              </button>
              {showPasses && (
                <ul className="divide-y divide-line-soft border-t border-line">
                  {passes.map((ck, i) => (
                    <CheckRow key={i} c={ck} categoryKey={c.key} />
                  ))}
                </ul>
              )}
            </>
          )}
        </>
      )}
    </div>
  );
}

function CategoryList({ categories }: { categories: ReportCategory[] }) {
  return (
    <div className="space-y-3">
      {categories.map((c) => (
        <CategoryCard key={c.key} c={c} />
      ))}
    </div>
  );
}

/** Every category at a glance — the whole report in one screen, before any scrolling. */
function GradeGrid({ categories }: { categories: ReportCategory[] }) {
  return (
    <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
      {categories.map((c) => {
        const fails = c.checks.filter((x) => !x.pass).length;
        return (
          <div
            key={c.key}
            className={`border bg-panel px-3 py-2.5 ${fails > 0 ? 'border-danger/40' : 'border-line'}`}
          >
            <div className="flex items-start justify-between gap-2">
              <p className="font-mono text-[11px] uppercase leading-tight tracking-wide text-muted">{c.label}</p>
              <span className={`shrink-0 font-mono text-sm font-semibold ${tone(c.grade).split(' ')[0]}`}>
                {c.grade ?? '—'}
              </span>
            </div>
            <p className={`mt-1 font-mono text-[11px] ${fails > 0 ? 'text-danger' : 'text-faint'}`}>
              {fails > 0 ? `${fails} to fix` : 'all clear'}
            </p>
            <PassBar passed={c.checks.length - fails} total={c.checks.length} className="mt-2" />
          </div>
        );
      })}
    </div>
  );
}

function downloadSbom(result: RepoScanResult): void {
  const deps = result.dependencies ?? [];
  if (deps.length === 0) return;
  // Real web app (not the artifact sandbox), so a client-side blob download works.
  const bom = toCycloneDX(deps, result.ref, new Date().toISOString());
  const blob = new Blob([JSON.stringify(bom, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `${result.ref.replace('/', '-')}-sbom.cdx.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function repoFix(f: RepoFinding): string {
  if (f.kind === 'dockerfile') {
    return 'Harden the Dockerfile: add a non-root `USER`, pin the base image to a specific version or digest (not :latest), never bake secrets into ENV/ARG (pass them at runtime), and avoid ADD-from-URL or piping downloads into a shell.';
  }
  if (f.kind === 'dependency') {
    return f.label.startsWith('MALICIOUS')
      ? 'Remove this package immediately — it is flagged as malicious. Then rotate every credential that was present on any machine that ran an install (the package may have exfiltrated them), and audit your lockfile for anything else it pulled in.'
      : 'Update this dependency to a patched version — `npm audit fix`, or bump it directly and reinstall. If nothing depends on it directly, it came in transitively: update the parent package or add an override.';
  }
  if (f.kind === 'secret') {
    return 'This is committed to the repo, so treat it as compromised: ROTATE the key, then load it from an environment variable instead of source. Remove it from the working tree (git rm --cached), add the file to .gitignore, and if it is sensitive, rewrite history so it is not recoverable from old commits.';
  }
  return "Scope the query to the caller's organisation, not just the id — e.g. add `.eq('organization_id', user.organization_id)` (or your tenant column). Then install tenant-guard so CI fails whenever a route filters by a bare id without scoping to a tenant.";
}

const REPO_SEV: Record<RepoFinding['severity'], string> = {
  critical: 'text-danger',
  high: 'text-danger/80',
  medium: 'text-warn',
};

function RepoReport({ result, onReset }: { result: RepoScanResult; onReset: () => void }) {
  return (
    <section>
      <div className={`border bg-panel ${result.findings.length > 0 ? 'border-danger/40' : 'border-safe/40'}`}>
        <div className="flex items-stretch">
          <div className={`flex w-24 shrink-0 items-center justify-center border-r font-mono text-6xl font-semibold sm:w-32 sm:text-7xl ${tone(result.grade)}`}>
            {result.grade}
          </div>
          <div className="flex min-w-0 flex-col justify-center px-5 py-5">
            <p className="kicker mb-1.5">Repo scan</p>
            <p className="truncate font-mono text-xs text-faint">{result.ref}</p>
            <p className="mt-1.5 font-display text-lg leading-snug text-ink">{result.summary}</p>
          </div>
        </div>
      </div>

      {result.findings.length > 0 ? (
        <div className="mt-4 space-y-3">
          {result.findings.map((f, i) => (
            <div key={i} className="border border-danger/30 bg-panel p-4">
              <div className="flex items-start gap-2.5">
                <span className={`mt-px font-mono text-sm ${REPO_SEV[f.severity]}`}>✗</span>
                <div className="min-w-0 flex-1">
                  <p className="text-sm text-ink">{f.label}</p>
                  <p className="mt-0.5 break-words font-mono text-xs text-faint">{f.detail}</p>
                  <p className="mt-1.5 border-l border-warn/40 pl-2.5 text-xs leading-relaxed text-muted">
                    <span className="text-warn">Fix: </span>
                    {repoFix(f)}
                  </p>
                </div>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <p className="mt-4 font-mono text-xs text-muted">
          <span className="text-safe">✓</span> {result.filesScanned} source file(s) scanned, nothing found. Tests, fixtures and examples are skipped.
        </p>
      )}

      <div className="mt-6 border border-line bg-panel p-5">
        <p className="kicker mb-2">Private repo?</p>
        <p className="text-sm leading-relaxed text-muted">
          This scans public repos from the outside. For your real (private) repo, run the same checks — plus a live
          Postgres proof that one tenant cannot read another — in CI:
        </p>
        <code className="mt-3 block border border-line bg-canvas px-3 py-2 font-mono text-xs text-safe">npx tenant-guard init</code>
      </div>

      <div className="mt-8 flex flex-wrap gap-3">
        <button onClick={onReset} className="border border-line px-4 py-2 font-mono text-xs text-muted transition-colors hover:border-ink hover:text-ink">
          ↺ scan another
        </button>
        {(result.dependencies?.length ?? 0) > 0 && (
          <button
            onClick={() => downloadSbom(result)}
            className="border border-line px-4 py-2 font-mono text-xs text-muted transition-colors hover:border-ink hover:text-ink"
          >
            ↓ download SBOM (CycloneDX · {result.dependencies!.length} deps)
          </button>
        )}
      </div>
    </section>
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
  const [skipped, setSkipped] = useState<string[]>([]);
  const [rateLimited, setRateLimited] = useState(false);
  const [mode, setMode] = useState<'url' | 'repo'>('url');
  const [repoUrl, setRepoUrl] = useState('');
  const [repoResult, setRepoResult] = useState<RepoScanResult | null>(null);
  const [repoLoading, setRepoLoading] = useState(false);
  const [repoError, setRepoError] = useState('');
  const [notifyEmail, setNotifyEmail] = useState('');
  const [notifyState, setNotifyState] = useState<'idle' | 'sending' | 'done' | 'error'>('idle');
  const [notifyError, setNotifyError] = useState('');
  const [done, setDone] = useState<string[]>([]);
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
    setSkipped([]);
    setRateLimited(false);
    setDone([]);
    // A check that could not RUN must never look like a check that PASSED, so
    // every failure is recorded and surfaced rather than silently dropped.
    const failed: string[] = [];
    let limited = false;
    const postScan = <T,>(endpoint: string, label: string): Promise<T | null> =>
      fetch(endpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ url: appUrl }),
      })
        .then(async (r) => {
          if (r.status === 429) {
            limited = true;
            failed.push(label);
            return null;
          }
          const j = await r.json().catch(() => null);
          if (!j || j.error) {
            failed.push(label);
            return null;
          }
          return j as T;
        })
        .catch(() => {
          failed.push(label);
          return null;
        })
        .finally(() => setDone((d) => (d.includes(label) ? d : [...d, label])));

    const headersP = appUrl.trim() ? postScan<HeadersScanResult>('/api/scan/headers', 'security headers') : Promise.resolve(null);
    const pathsP = appUrl.trim() ? postScan<PathsScanResult>('/api/scan/paths', 'exposed files') : Promise.resolve(null);
    const secretsP = appUrl.trim()
      ? postScan<
          SecretsScanResult & {
            discovered?: { url: string; anonKey: string } | null;
            firebase?: FirebaseConfig | null;
            firebaseCollections?: string[];
          }
        >('/api/scan/secrets', 'secrets')
      : Promise.resolve(null);
    const fundamentalsP = appUrl.trim() ? postScan<FundamentalsResult>('/api/scan/fundamentals', 'fundamentals') : Promise.resolve(null);
    const routesP = appUrl.trim() ? postScan<RoutesScanResult>('/api/scan/routes', 'admin & debug routes') : Promise.resolve(null);
    const aiP = appUrl.trim() ? postScan<AiSurfaceResult>('/api/scan/ai', 'AI & MCP endpoints') : Promise.resolve(null);
    const privacyP = appUrl.trim() ? postScan<PrivacyResult>('/api/scan/privacy', 'EU privacy') : Promise.resolve(null);
    const emailP = appUrl.trim() ? postScan<EmailAuthResult>('/api/scan/email', 'email spoofing') : Promise.resolve(null);
    const transportP = appUrl.trim() ? postScan<TransportResult>('/api/scan/transport', 'HTTPS & redirects') : Promise.resolve(null);
    const visibilityP = appUrl.trim() ? postScan<VisibilityResult>('/api/scan/visibility', 'AI & search visibility') : Promise.resolve(null);
    try {
      const [hdr, paths, secrets, fundamentals, routes, ai, privacy, email, transport, visibility] = await Promise.all([headersP, pathsP, secretsP, fundamentalsP, routesP, aiP, privacyP, emailP, transportP, visibilityP]);
      if (appUrl.trim()) {
        if (limited) {
          // The app is fine — we are. Saying "could not reach your app" here
          // sends people debugging a problem that does not exist.
          setError('Too many scans from your network in the last minute. Wait a moment and run it again — nothing is wrong with your app.');
        } else if (!hdr && !paths && !secrets && !fundamentals) {
          setError('Could not reach that app URL — is it live and public?');
        }
        setSkipped(failed);
        setRateLimited(limited);
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

      const base: ReportInputs = { supabase: sb, firebase: fb, headers: hdr, paths, routes, ai, secrets, fundamentals, privacy, email, transport, visibility };
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

  async function joinWaitlist(e: React.FormEvent) {
    e.preventDefault();
    if (notifyState === 'sending') return;
    setNotifyState('sending');
    setNotifyError('');
    try {
      const r = await fetch('/api/notify', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email: notifyEmail }),
      });
      const j = await r.json().catch(() => null);
      if (r.ok && j?.ok) setNotifyState('done');
      else {
        setNotifyError(j?.error ?? 'Could not add you just now.');
        setNotifyState('error');
      }
    } catch {
      setNotifyError('Could not add you just now.');
      setNotifyState('error');
    }
  }

  async function runRepo(e: React.FormEvent) {
    e.preventDefault();
    if (!repoUrl.trim() || repoLoading) return;
    setRepoLoading(true);
    setRepoError('');
    setRepoResult(null);
    try {
      const r = await fetch('/api/scan/repo', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ repo: repoUrl }),
      });
      const j = (await r.json()) as RepoScanResult;
      if (r.ok && j.ok) setRepoResult(j);
      else setRepoError(j.error ?? 'Could not scan that repository.');
    } catch {
      setRepoError('Could not scan that repository.');
    } finally {
      setRepoLoading(false);
    }
  }

  function reset() {
    setInputs(null);
    setError('');
    setLhLoading(false);
    setSkipped([]);
    setRateLimited(false);
    setDone([]);
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

      {!report && !repoResult && (
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

          <div className="mb-6 flex gap-1 border border-line bg-panel p-1 font-mono text-xs">
            <button
              onClick={() => setMode('url')}
              className={`flex-1 px-3 py-2 uppercase tracking-wider transition ${mode === 'url' ? 'bg-ink text-canvas' : 'text-muted hover:text-ink'}`}
            >
              Live app
            </button>
            <button
              onClick={() => setMode('repo')}
              className={`flex-1 px-3 py-2 uppercase tracking-wider transition ${mode === 'repo' ? 'bg-ink text-canvas' : 'text-muted hover:text-ink'}`}
            >
              Public repo
            </button>
          </div>

          {mode === 'url' && (
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
          )}

          {mode === 'repo' && (
            <form onSubmit={runRepo} className="border border-line bg-panel">
              <div className="border-b border-line p-4">
                <label className="kicker block mb-2">Public GitHub repo</label>
                <input
                  value={repoUrl}
                  onChange={(e) => setRepoUrl(e.target.value)}
                  placeholder="github.com/owner/repo"
                  className="w-full bg-transparent font-mono text-base text-ink placeholder-faint outline-none sm:text-sm"
                />
              </div>
              <div className="flex items-center justify-between p-4">
                <span className="kicker text-faint">source-level · public repos only</span>
                <button
                  type="submit"
                  disabled={repoLoading}
                  className="border border-ink bg-ink px-5 py-2 font-mono text-xs font-medium uppercase tracking-wider text-canvas transition hover:bg-transparent hover:text-ink disabled:opacity-40"
                >
                  {repoLoading ? 'scanning…' : 'scan repo →'}
                </button>
              </div>
            </form>
          )}

          {mode === 'repo' && repoLoading && (
            <div className="mt-4 flex items-center gap-2.5 border border-line bg-panel px-4 py-3">
              <span className="inline-block h-2 w-2 shrink-0 animate-pulse rounded-full bg-warn" />
              <p className="font-mono text-xs text-muted">Fetching source &amp; running checks — committed secrets, cross-tenant routes…</p>
            </div>
          )}
          {mode === 'repo' && repoError && <p className="mt-4 font-mono text-xs text-danger">{repoError}</p>}

          {loading && (
            <div className="mt-4 border border-line bg-panel">
              <div className="flex items-center justify-between border-b border-line px-4 py-2.5">
                <div className="flex items-center gap-2.5">
                  <span className="inline-block h-2 w-2 shrink-0 animate-pulse rounded-full bg-warn" />
                  <p className="font-mono text-xs uppercase tracking-wider text-ink">Scanning</p>
                </div>
                <p className="font-mono text-xs text-faint">
                  {done.length}/{SCAN_STEPS.length}
                </p>
              </div>
              <ul className="grid grid-cols-1 gap-x-4 px-4 py-3 sm:grid-cols-2">
                {SCAN_STEPS.map((label) => {
                  const isDone = done.includes(label);
                  return (
                    <li key={label} className="flex items-center gap-2 py-1 font-mono text-xs">
                      <span className={isDone ? 'text-safe' : 'text-faint'}>{isDone ? '✓' : '·'}</span>
                      <span className={isDone ? 'text-muted' : 'text-faint'}>{label}</span>
                    </li>
                  );
                })}
              </ul>
            </div>
          )}

          {error && <p className="mt-4 font-mono text-xs text-danger">{error}</p>}

          <p className="mt-6 text-xs leading-relaxed text-faint">
            Every other scanner queries your database from <em>their</em> servers. vibecheck runs the
            database probes in <span className="text-muted">your own browser</span> — we never query
            it, and we store nothing. It only ever reads what any visitor can already reach.
          </p>
        </>
      )}

      {repoResult && <RepoReport result={repoResult} onReset={() => { setRepoResult(null); setRepoError(''); }} />}

      {report && (
        <section>
          {/* the headline — this is the screenshot people share */}
          <div className={`border bg-panel ${report.issueCount > 0 ? 'border-danger/40' : 'border-safe/40'}`}>
            <div className="flex items-stretch">
              <div
                className={`flex w-24 shrink-0 items-center justify-center border-r font-mono text-6xl font-semibold sm:w-32 sm:text-7xl ${tone(
                  report.overallGrade,
                )}`}
              >
                {report.overallGrade}
              </div>
              <div className="flex min-w-0 flex-col justify-center px-5 py-5">
                <p className="kicker mb-1.5">Security grade</p>
                {appUrl.trim() && (
                  <p className="mb-1.5 truncate font-mono text-xs text-faint">
                    {appUrl.replace(/^https?:\/\//, '').replace(/\/.*$/, '')}
                  </p>
                )}
                <p className="font-display text-lg leading-snug text-ink sm:text-xl">{report.verdict}</p>
              </div>
            </div>
            {/* one honest metric row, not a dashboard */}
            <div className="flex divide-x divide-line border-t border-line">
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
            <PassBar passed={report.passed} total={report.total} />
          </div>

          {autoDetected && (
            <p className="mt-3 font-mono text-xs text-muted">
              <span className="text-safe">✓</span> Found your backend in the app&apos;s own bundle and probed
              it <span className="text-ink">from your browser</span> — nothing was sent to our servers.
            </p>
          )}

          {/* everything at a glance, before any scrolling */}
          <div className="mt-3">
            <GradeGrid categories={report.categories} />
          </div>

          {report.issueCount > 0 && (
            <div className="mt-3">
              <SeverityBreakdown report={report} />
            </div>
          )}

          {/* security categories — the headline */}
          <div className="mt-6">
            <CategoryList categories={report.categories.filter((c) => c.group === 'security')} />
          </div>

          {error && <p className="mt-4 font-mono text-xs text-warn">{error}</p>}

          {skipped.length > 0 && (
            <div className="mt-4 border border-warn/40 bg-panel px-4 py-3">
              <p className="font-mono text-xs text-warn">
                {skipped.length} check{skipped.length === 1 ? '' : 's'} could not run
                {rateLimited ? ' (rate limited)' : ''}: <span className="text-muted">{skipped.join(', ')}</span>
              </p>
              <p className="mt-1 text-xs leading-relaxed text-faint">
                This report is incomplete — those areas were not checked, which is not the same as them
                being clean. Run the scan again in a minute for the full picture.
              </p>
            </div>
          )}

          {/* What a URL scanner genuinely cannot see — stated plainly, because a
              silent limit reads as "checked and clean". Only shown when a
              database was actually found, since otherwise it is irrelevant. */}
          {report.categories.some((c) => c.key === 'supabase' || c.key === 'firebase') && (
            <div className="mt-6 border border-line bg-panel p-5">
              <p className="kicker mb-2">What this scan cannot see</p>
              <p className="text-sm leading-relaxed text-muted">
                vibecheck looks at your app from the outside — the same view a stranger has. Some
                failures only exist inside your code, and no URL scanner can reach them:
              </p>
              <ul className="mt-3 space-y-1.5">
                {[
                  'an API route that forgets to filter by organisation (one user reading another tenant’s data)',
                  'whether RLS isolates tenants on WRITES, not just reads',
                  'a policy that exists only in production and in no migration',
                  'SECURITY DEFINER functions the anon role can still execute',
                ].map((t) => (
                  <li key={t} className="flex items-start gap-2 text-xs leading-relaxed text-faint">
                    <span className="mt-px text-muted">·</span>
                    <span>{t}</span>
                  </li>
                ))}
              </ul>
              <p className="mt-3 text-sm text-muted">
                Those run in your repo, against a test database, as CI tests that fail the build:
              </p>
              <code className="mt-2 block border border-line bg-canvas px-3 py-2 font-mono text-xs text-safe">
                npx tenant-guard prove
              </code>
              <a
                href="https://github.com/FedericoTs/tenant-guard"
                className="mt-3 inline-block font-mono text-xs text-muted transition-colors hover:text-ink"
              >
                tenant-guard — free &amp; open source ↗
              </a>
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
                Visibility, fundamentals &amp; performance <span className="text-faint">· separate from the security grade</span>
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

      {report && WAITLIST_ENABLED && (
        <section className="mt-10 border border-line bg-panel p-5">
          {notifyState === 'done' ? (
            <p className="font-mono text-xs text-safe">
              ✓ You&apos;re on the list. We&apos;ll email you when monitoring is ready — nothing else.
            </p>
          ) : (
            <>
              <p className="kicker mb-2">Want to know if this changes?</p>
              <p className="text-sm leading-relaxed text-muted">
                Apps drift. A key gets committed, a policy gets loosened, a certificate lapses. Leave your
                email and we&apos;ll re-check weekly and tell you if something breaks.
              </p>
              <form onSubmit={joinWaitlist} className="mt-4 flex flex-col gap-2 sm:flex-row">
                <input
                  type="email"
                  required
                  value={notifyEmail}
                  onChange={(e) => setNotifyEmail(e.target.value)}
                  placeholder="you@yourdomain.com"
                  className="min-w-0 flex-1 border border-line bg-canvas px-3 py-2.5 font-mono text-base text-ink placeholder-faint outline-none focus:border-ink sm:text-xs"
                />
                <button
                  type="submit"
                  disabled={notifyState === 'sending'}
                  className="border border-ink bg-ink px-5 py-2.5 font-mono text-xs font-medium uppercase tracking-wider text-canvas transition hover:bg-transparent hover:text-ink disabled:opacity-40"
                >
                  {notifyState === 'sending' ? 'adding…' : 'notify me'}
                </button>
              </form>
              {notifyState === 'error' && <p className="mt-2 font-mono text-xs text-danger">{notifyError}</p>}
              <p className="mt-3 text-xs leading-relaxed text-faint">
                Only your email is stored, and only because you typed it. Your scan stays anonymous — we
                never record the app you checked or what we found.
              </p>
            </>
          )}
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
