'use client';

import { useState, useMemo, useEffect, useRef } from 'react';
import Link from 'next/link';
import { track } from '@vercel/analytics';
import { scanSupabase } from '@/lib/scan/supabase';
import { scanFirebase, extractCollections, firebaseConfigFromText, type FirebaseConfig } from '@/lib/scan/firebase';
import { unzipSync } from 'fflate';
import { extractScannableText, analyzeBinaryText } from '@/lib/scan/binary';
import { combineReport, type ReportInputs, type ReportCategory, type CheckItem } from '@/lib/scan/report';
import { buildFixPrompt, buildRepoFixPrompt, fixFor } from '@/lib/scan/fixes';
import { tone, PassBar, ScoreDial, SeverityBar, CategoryMatrix, LighthouseGauges, WebVitals, CrawlerMatrix } from '@/components/report-visuals';
import type { HeadersScanResult } from '@/lib/scan/headers';
import type { PathsScanResult } from '@/lib/scan/paths';
import type { RoutesScanResult } from '@/lib/scan/routes';
import type { AiSurfaceResult } from '@/lib/scan/ai-surface';
import type { PrivacyResult } from '@/lib/scan/privacy';
import type { EmailAuthResult } from '@/lib/scan/email-auth';
import type { TransportResult } from '@/lib/scan/transport';
import type { VisibilityResult } from '@/lib/scan/visibility';
import type { SmugglingResult } from '@/lib/scan/smuggling';
import type { DevServerResult } from '@/lib/scan/devserver';
import type { ScaffoldResult } from '@/lib/scan/scaffold';
import type { RepoScanResult, RepoFinding } from '@/lib/scan/repo';
import { toCycloneDX } from '@/lib/scan/sbom';
import { gradeSecrets, type SecretsScanResult } from '@/lib/scan/secrets';
import type { LibsScanResult } from '@/lib/scan/libs';
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
  'production build',
  'fundamentals',
];

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
  const [promptCopied, setPromptCopied] = useState(false);
  const [badgeMdCopied, setBadgeMdCopied] = useState(false);
  // A repo scan reads the default branch at one moment, so the badge is stamped.
  const repoBadgeDate = new Date().toLocaleDateString('en-US', { month: 'short', year: 'numeric' });

  function copyPrompt(): void {
    track('repo_fix_prompt_copied', { grade: result.grade, issues: result.findings.length });
    const text = buildRepoFixPrompt(
      { ref: result.ref, filesScanned: result.filesScanned, findings: result.findings },
      (f) => repoFix(f as RepoFinding),
    );
    navigator.clipboard?.writeText(text).then(() => {
      setPromptCopied(true);
      setTimeout(() => setPromptCopied(false), 2200);
    });
  }

  function copyBadgeMd(): void {
    const origin = window.location.origin;
    const md = `[![vibecheck — no issues found in the repo, ${repoBadgeDate}](${origin}/badge?g=${result.grade}&d=${encodeURIComponent(repoBadgeDate)})](${origin})`;
    navigator.clipboard?.writeText(md).then(() => {
      setBadgeMdCopied(true);
      setTimeout(() => setBadgeMdCopied(false), 2200);
    });
  }

  return (
    <section>
      <div className={`border bg-panel ${result.findings.length > 0 ? 'border-danger/40' : 'border-safe/40'}`}>
        <div className="flex flex-col items-center gap-5 p-6 text-center sm:flex-row sm:items-center sm:gap-7 sm:text-left">
          <ScoreDial grade={result.grade} />
          <div className="flex min-w-0 flex-1 flex-col justify-center">
            <p className="kicker mb-1.5">Repo scan</p>
            <p className="truncate font-mono text-xs text-faint">{result.ref}</p>
            <p className="mt-1.5 font-display text-lg leading-snug text-ink sm:text-xl">{result.summary}</p>
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

      {/*
        The fix prompt, and it beats the URL one: every repo finding carries the
        file it came from, so the agent is pointed at a path instead of being
        asked to go looking.
      */}
      {result.findings.length > 0 && (
        <button
          onClick={copyPrompt}
          className="mt-6 w-full border border-warn bg-warn/10 px-5 py-3 font-mono text-xs font-medium uppercase tracking-wider text-warn transition hover:bg-warn/20"
        >
          {promptCopied
            ? '✓ copied — paste it into Cursor, Claude Code or your editor'
            : `⚡ copy the fix prompt (${result.findings.length} issue${result.findings.length === 1 ? '' : 's'}, with file paths)`}
        </button>
      )}

      {/* A clean repo earns the same badge a clean URL scan does. Date-stamped,
          because it describes the default branch at one moment. */}
      {result.findings.length === 0 && (
        <div className="mt-6 border border-safe/30 bg-panel p-5">
          <p className="kicker mb-2 text-safe">Clean scan — show it off</p>
          <p className="text-sm text-muted">
            Drop it in your README. It is <span className="text-ink">date-stamped</span> — this reflects the
            default branch when it was scanned, not a standing promise — and links back so anyone can re-check.
          </p>
          <div className="mt-3 flex flex-wrap items-center gap-3">
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img
              src={`/badge?g=${result.grade}&d=${encodeURIComponent(repoBadgeDate)}`}
              alt={`vibecheck — no issues found in the repo, ${repoBadgeDate}`}
              width={288}
              height={20}
            />
            <button
              onClick={copyBadgeMd}
              className="border border-line px-3 py-1.5 font-mono text-xs text-muted transition-colors hover:border-ink hover:text-ink"
            >
              {badgeMdCopied ? '✓ markdown copied' : 'copy markdown'}
            </button>
          </div>
        </div>
      )}

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
  const [mode, setMode] = useState<'url' | 'repo' | 'backend'>('url');
  const [fbConfig, setFbConfig] = useState('');
  const [repoUrl, setRepoUrl] = useState('');
  const [repoResult, setRepoResult] = useState<RepoScanResult | null>(null);
  const [repoLoading, setRepoLoading] = useState(false);
  const [repoError, setRepoError] = useState('');
  const [notifyEmail, setNotifyEmail] = useState('');
  const [notifyState, setNotifyState] = useState<'idle' | 'sending' | 'done' | 'error'>('idle');
  const [notifyError, setNotifyError] = useState('');
  const [done, setDone] = useState<string[]>([]);
  const report = useMemo(() => (inputs ? combineReport(inputs) : null), [inputs]);
  // Point-in-time stamp for the share badge — a scan is a moment, not a standing promise.
  const badgeDate = new Date().toLocaleDateString('en-US', { month: 'short', year: 'numeric' });

  // Anonymous, cookieless usage analytics. We record the grade, the mode, and the
  // issue COUNT — never the URL, the key, or the findings — so "we never see your
  // app" stays literally true; this only tells us how the tool is used.
  const lastMode = useRef<'url' | 'backend' | 'mobile'>('url');
  useEffect(() => {
    if (report) track('scan_completed', { mode: lastMode.current, grade: report.overallGrade, issues: report.issueCount });
  }, [report]);
  useEffect(() => {
    if (repoResult) track('scan_completed', { mode: 'repo', grade: repoResult.grade, issues: repoResult.findings.length });
  }, [repoResult]);

  async function run(e: React.FormEvent) {
    e.preventDefault();
    setError('');
    if (!appUrl.trim() && !(sbUrl.trim() && anonKey.trim())) {
      setError('Enter your app URL, or add a Supabase project to check.');
      return;
    }
    lastMode.current = 'url';
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
            libraries?: LibsScanResult | null;
          }
        >('/api/scan/secrets', 'secrets')
      : Promise.resolve(null);
    const fundamentalsP = appUrl.trim() ? postScan<FundamentalsResult>('/api/scan/fundamentals', 'fundamentals') : Promise.resolve(null);
    const routesP = appUrl.trim() ? postScan<RoutesScanResult>('/api/scan/routes', 'admin & debug routes') : Promise.resolve(null);
    const aiP = appUrl.trim() ? postScan<AiSurfaceResult>('/api/scan/ai', 'AI & MCP endpoints') : Promise.resolve(null);
    const privacyP = appUrl.trim() ? postScan<PrivacyResult>('/api/scan/privacy', 'EU privacy') : Promise.resolve(null);
    const emailP = appUrl.trim() ? postScan<EmailAuthResult>('/api/scan/email', 'email spoofing') : Promise.resolve(null);
    const transportP = appUrl.trim() ? postScan<TransportResult>('/api/scan/transport', 'HTTPS & redirects') : Promise.resolve(null);
    const devServerP = appUrl.trim() ? postScan<DevServerResult & { scaffold?: ScaffoldResult }>('/api/scan/devserver', 'production build') : Promise.resolve(null);
    const visibilityP = appUrl.trim() ? postScan<VisibilityResult & { smuggling?: SmugglingResult }>('/api/scan/visibility', 'AI & search visibility') : Promise.resolve(null);
    try {
      const [hdr, paths, secrets, fundamentals, routes, ai, privacy, email, transport, visibility, devServer] = await Promise.all([headersP, pathsP, secretsP, fundamentalsP, routesP, aiP, privacyP, emailP, transportP, visibilityP, devServerP]);
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

      const base: ReportInputs = { supabase: sb, firebase: fb, headers: hdr, paths, routes, ai, secrets, fundamentals, privacy, email, transport, visibility, libraries: secrets?.libraries ?? null, smuggling: visibility?.smuggling ?? null, devServer, scaffold: devServer?.scaffold ?? null };
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

  /**
   * A pre-composed post. It opens X's compose window — the user still writes
   * and sends it themselves; nothing is posted on their behalf.
   *
   * The wording follows the result rather than flattening it: a clean scan and
   * a failing one are different stories, and overclaiming either would make the
   * share a lie. A clean result says what was checked, not "my app is secure".
   */
  const shareIntentUrl = useMemo(() => {
    // Guarded because a client component still renders once on the server —
    // though in practice `report` is null there, so this returns '#'.
    if (!report || typeof window === 'undefined') return '#';
    const url = `${window.location.origin}/r?g=${report.overallGrade}&i=${report.issueCount}&p=${report.passed}`;
    const n = report.issueCount;
    const text =
      n === 0
        ? `Scanned my app with vibecheck — ${report.passed} checks passed, no public exposure found. It looks at what a stranger can already read: exposed database tables, keys in the bundle, dev builds shipped live, source maps, hidden text aimed at AI. Free, no signup.`
        : `vibecheck found ${n} issue${n === 1 ? '' : 's'} in my AI-built app (graded ${report.overallGrade}). It shows what a stranger can already read — exposed tables, keys in the bundle, dev builds. Free, no signup, and it hands you the fix.`;
    return `https://twitter.com/intent/tweet?text=${encodeURIComponent(text)}&url=${encodeURIComponent(url)}`;
  }, [report]);

  function share() {
    if (!report) return;
    track('result_shared', { grade: report.overallGrade });
    // A shareable link that unfurls into the OG card — grade + issue count only,
    // never the host, key, or findings.
    const url = `${window.location.origin}/r?g=${report.overallGrade}&i=${report.issueCount}&p=${report.passed}`;
    navigator.clipboard?.writeText(url).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    });
  }

  function copyFixPrompt() {
    if (!report) return;
    track('fix_prompt_copied', { grade: report.overallGrade, issues: report.issueCount });
    // Deterministic prompt — no LLM, so it costs nothing and can't hallucinate a wrong fix.
    navigator.clipboard?.writeText(buildFixPrompt(report, appUrl.trim() || undefined)).then(() => {
      setFixCopied(true);
      setTimeout(() => setFixCopied(false), 2400);
    });
  }

  function copyBadge() {
    if (!report) return;
    const origin = window.location.origin;
    const md = `[![vibecheck — no public exposure found, ${badgeDate}](${origin}/badge?g=${report.overallGrade}&d=${encodeURIComponent(badgeDate)})](${origin})`;
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

  async function scanBinary(file: File) {
    setError('');
    lastMode.current = 'mobile';
    setLoading(true);
    setInputs(null);
    setAutoDetected(false);
    try {
      const buf = new Uint8Array(await file.arrayBuffer());
      // .apk / .ipa are ZIPs; the whole thing runs HERE — the binary never leaves the browser.
      if (!(buf[0] === 0x50 && buf[1] === 0x4b)) {
        setError('That does not look like an .apk or .ipa (they are ZIP archives).');
        return;
      }
      let files: Record<string, Uint8Array>;
      try {
        files = unzipSync(buf, { filter: (f) => !/\.(dex|so|png|jpe?g|webp|gif|ttf|otf|woff2?|dylib|nib|car)$/i.test(f.name) });
      } catch {
        setError('Could not unpack that archive — is it a valid .apk / .ipa?');
        return;
      }
      const { text } = extractScannableText(files);
      const { secrets, discovered, firebase } = analyzeBinaryText(text);
      const [sb, fb] = await Promise.all([
        discovered ? scanSupabase(discovered).catch(() => null) : Promise.resolve(null),
        firebase ? scanFirebase({ config: firebase, collections: extractCollections(text) }).catch(() => null) : Promise.resolve(null),
      ]);
      if (discovered || firebase) setAutoDetected(true);
      setInputs({ supabase: sb, firebase: fb, secrets: gradeSecrets(secrets, 'your app') });
    } catch {
      setError('Could not read that file.');
    } finally {
      setLoading(false);
    }
  }

  async function runBackend(e: React.FormEvent) {
    e.preventDefault();
    setError('');
    lastMode.current = 'backend';
    const hasSupa = sbUrl.trim() && anonKey.trim();
    const fb = fbConfig.trim() ? firebaseConfigFromText(fbConfig) : null;
    if (!hasSupa && !fb) {
      setError('Paste your Supabase URL + key, or your Firebase config.');
      return;
    }
    setLoading(true);
    setInputs(null);
    setAutoDetected(false);
    setSkipped([]);
    try {
      // A mobile / headless app has no scannable page, but it embeds the same
      // backend config a web app does — so the database checks apply identically,
      // and still run in the browser.
      const [sb, firebase] = await Promise.all([
        hasSupa ? scanSupabase({ url: sbUrl, anonKey }) : Promise.resolve(null),
        fb ? scanFirebase({ config: fb, collections: extractCollections(fbConfig) }).catch(() => null) : Promise.resolve(null),
      ]);
      // A report is only meaningful if at least one probe actually ran. An
      // errored Supabase alone (e.g. a rotated key) would otherwise render a
      // misleading grade-C / 0-checks card, so surface its message instead.
      if ((sb && sb.ok) || firebase) setInputs({ supabase: sb, firebase });
      else setError(sb && !sb.ok ? sb.error ?? 'Could not reach that backend.' : 'Could not reach that backend — double-check the values you pasted.');
    } finally {
      setLoading(false);
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
    // The repo result also hides the form, so clearing it is part of going home.
    setRepoResult(null);
    setRepoError('');
    window.scrollTo({ top: 0 });
  }

  return (
    <main className="mx-auto w-full max-w-2xl px-5 py-10 sm:py-16">
      {/* status bar — doubles as the way home once a result has replaced the form */}
      <div className="mb-14 flex items-center justify-between kicker">
        {report || repoResult ? (
          <button
            onClick={reset}
            className="-my-2 py-2 text-muted transition-colors hover:text-ink"
            aria-label="Back to the scanner"
          >
            ← vibecheck ▸ scan another
          </button>
        ) : (
          <span>vibecheck ▸ security scan</span>
        )}
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
            <button
              onClick={() => setMode('backend')}
              className={`flex-1 px-3 py-2 uppercase tracking-wider transition ${mode === 'backend' ? 'bg-ink text-canvas' : 'text-muted hover:text-ink'}`}
            >
              App backend
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

          {mode === 'backend' && (
            <form onSubmit={runBackend} className="border border-line bg-panel">
              <div className="border-b border-line p-4">
                <p className="mb-3 text-xs leading-relaxed text-muted">
                  No public web page to point at — a mobile app, an API, anything headless? Paste the backend
                  config it ships. The database checks run in <span className="text-ink">your browser</span>, exactly
                  like a web scan, because the risk lives in the backend, not the client.
                </p>
                <label className="kicker block mb-2">Supabase</label>
                <input
                  value={sbUrl}
                  onChange={(e) => setSbUrl(e.target.value)}
                  placeholder="https://xxxxxxxx.supabase.co"
                  className="w-full bg-transparent font-mono text-base text-ink placeholder-faint outline-none sm:text-sm"
                />
                <input
                  value={anonKey}
                  onChange={(e) => setAnonKey(e.target.value)}
                  placeholder="anon / publishable key (eyJ… or sb_publishable_…)"
                  className="mt-2 w-full bg-transparent font-mono text-base text-ink placeholder-faint outline-none sm:text-xs"
                />
              </div>
              <div className="border-b border-line p-4">
                <label className="kicker block mb-2">…or Firebase</label>
                <textarea
                  value={fbConfig}
                  onChange={(e) => setFbConfig(e.target.value)}
                  rows={4}
                  placeholder='paste your firebaseConfig (projectId, apiKey, storageBucket)'
                  className="w-full resize-none bg-transparent font-mono text-base text-ink placeholder-faint outline-none sm:text-xs"
                />
              </div>
              <div className="border-b border-line p-4">
                <label className="kicker block mb-2">…or upload your app (.apk / .ipa)</label>
                <input
                  type="file"
                  accept=".apk,.ipa,application/zip,application/vnd.android.package-archive"
                  onChange={(e) => {
                    const f = e.target.files?.[0];
                    if (f) scanBinary(f);
                  }}
                  className="w-full font-mono text-xs text-muted file:mr-3 file:border file:border-line file:bg-canvas file:px-3 file:py-1.5 file:font-mono file:text-xs file:text-ink hover:file:border-ink"
                />
                <p className="mt-2 text-xs leading-relaxed text-faint">
                  We unzip it and scan the JS bundle for secrets + backend config <span className="text-muted">in your browser</span> — the file never leaves your device. Works for React&nbsp;Native / Expo / Flutter apps.
                </p>
              </div>
              <div className="flex items-center justify-between p-4">
                <span className="kicker text-faint">runs in your browser · we never see your data</span>
                <button
                  type="submit"
                  disabled={loading}
                  className="border border-ink bg-ink px-5 py-2 font-mono text-xs font-medium uppercase tracking-wider text-canvas transition hover:bg-transparent hover:text-ink disabled:opacity-40"
                >
                  {loading ? 'checking…' : 'check backend →'}
                </button>
              </div>
            </form>
          )}

          {loading && mode === 'backend' && (
            <div className="mt-4 flex items-center gap-2.5 border border-line bg-panel px-4 py-3">
              <span className="inline-block h-2 w-2 shrink-0 animate-pulse rounded-full bg-warn" />
              <p className="font-mono text-xs text-muted">Probing your backend from this browser — tables, storage, auth config…</p>
            </div>
          )}

          {loading && mode === 'url' && (
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

          <p className="mt-3 kicker text-faint">
            Scan apps you own or are authorized to test ·{' '}
            <Link href="/legal" className="-my-1 inline-block py-1 transition-colors hover:text-ink">
              terms &amp; privacy
            </Link>
          </p>
        </>
      )}

      {repoResult && <RepoReport result={repoResult} onReset={() => { setRepoResult(null); setRepoError(''); }} />}

      {report && (
        <section>
          {/* the headline — this is the screenshot people share */}
          <div className={`border bg-panel ${report.issueCount > 0 ? 'border-danger/40' : 'border-safe/40'}`}>
            <div className="flex flex-col items-center gap-5 p-6 text-center sm:flex-row sm:items-center sm:gap-7 sm:text-left">
              <ScoreDial grade={report.overallGrade} />
              <div className="flex min-w-0 flex-1 flex-col justify-center">
                <p className="kicker mb-2">Security grade</p>
                {appUrl.trim() && (
                  <p className="mb-2 truncate font-mono text-xs text-faint">
                    {appUrl.replace(/^https?:\/\//, '').replace(/\/.*$/, '')}
                  </p>
                )}
                <p className="font-display text-xl leading-snug text-ink sm:text-2xl">{report.verdict}</p>
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

          {/* how bad is it — the shape of the damage, before the where and the what */}
          {report.issueCount > 0 && (
            <div className="mt-3">
              <SeverityBar report={report} />
            </div>
          )}

          {/* every category at a glance — failing tiles first, before any scrolling */}
          <div className="mt-3">
            <CategoryMatrix categories={report.categories} />
          </div>

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
              {inputs?.lighthouse?.scores && (
                <div className="mb-3 border border-line bg-panel p-5">
                  <div className="mb-5 flex items-baseline justify-between">
                    <p className="kicker">Google Lighthouse</p>
                    <p className="font-mono text-xs text-faint">0–100 · real PageSpeed scores</p>
                  </div>
                  <LighthouseGauges scores={inputs.lighthouse.scores} />
                  {inputs.lighthouse.cwv && <WebVitals cwv={inputs.lighthouse.cwv} />}
                </div>
              )}
              {inputs?.visibility?.crawlers && inputs.visibility.crawlers.length > 0 && (
                <div className="mb-3">
                  <CrawlerMatrix crawlers={inputs.visibility.crawlers} />
                </div>
              )}
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
                Add it to your README or footer. It&apos;s <span className="text-ink">date-stamped</span> — a scan is a
                point in time, not a guarantee — and links back so anyone can re-check.
              </p>
              <div className="mt-3 flex items-center gap-3">
                {/* eslint-disable-next-line @next/next/no-img-element */}
                <img
                  src={`/badge?g=${report.overallGrade}&d=${encodeURIComponent(badgeDate)}`}
                  alt={`vibecheck — no public exposure found, ${badgeDate}`}
                  width={288}
                  height={20}
                />
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
            {/*
              Share. The reason people do not post a security result is the fear
              of pointing strangers at their app — so show them the exact card
              that will unfurl, and say plainly what the link does NOT carry.
              Both statements are true: /r takes only a grade and a count.
            */}
            <div className="border border-line bg-panel p-5">
              <div className="mb-3 flex items-baseline justify-between gap-3">
                <p className="kicker">Share your result</p>
                <p className="font-mono text-[11px] text-faint">grade only · no URL</p>
              </div>
              {/* eslint-disable-next-line @next/next/no-img-element */}
              <img
                src={`/api/og?g=${report.overallGrade}&i=${report.issueCount}&p=${report.passed}`}
                alt={`Preview of the card that will appear when you share: grade ${report.overallGrade}, ${report.issueCount} issue${report.issueCount === 1 ? '' : 's'}`}
                width={1200}
                height={630}
                loading="lazy"
                className="w-full border border-line"
              />
              <p className="mt-3 text-xs leading-relaxed text-faint">
                This is exactly what people see. Your URL, your keys and the findings themselves are
                never in the link — only the grade and the number of issues.
              </p>
              <div className="mt-4 grid gap-2 sm:grid-cols-2">
                <a
                  href={shareIntentUrl}
                  target="_blank"
                  rel="noreferrer"
                  onClick={() => track('result_shared', { grade: report.overallGrade, channel: 'x' })}
                  className="flex items-center justify-center gap-2 border border-ink bg-ink px-5 py-3 font-mono text-xs font-medium uppercase tracking-wider text-canvas transition hover:bg-transparent hover:text-ink"
                >
                  <span className="text-sm font-semibold">𝕏</span> post it
                </a>
                <button
                  onClick={share}
                  className="border border-line px-5 py-3 font-mono text-xs font-medium uppercase tracking-wider text-muted transition hover:border-ink hover:text-ink"
                >
                  {copied ? '✓ link copied' : 'copy link'}
                </button>
              </div>
            </div>
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
        <div className="mt-5 flex flex-wrap items-center gap-4">
          <p className="kicker text-faint">
            free · open source · no signup · MIT ·{' '}
            <a href={X_URL} className="-my-1 inline-block py-1 transition-colors hover:text-ink">
              @federico_sciuca
            </a>{' '}
            ·{' '}
            <Link href="/legal" className="-my-1 inline-block py-1 transition-colors hover:text-ink">
              terms &amp; privacy
            </Link>
          </p>
          {/* Featured-on badge — inline, right-aligned. SSR-rendered (visible, not JS-only),
              href/src unchanged, no forbidden rel. referrerPolicy stops the third-party image
              from leaking a visitor's page URL to divvlaunches.com; lazy/async so their host
              being slow or down never blocks or shifts our layout. */}
          <a
            href="https://divvlaunches.com"
            aria-label="Featured on DivvLaunches"
            className="ml-auto inline-block shrink-0"
          >
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img
              src="https://www.divvlaunches.com/divvlaunches-featured-badge.png"
              alt="Featured on DivvLaunches"
              width={320}
              height={90}
              loading="lazy"
              decoding="async"
              referrerPolicy="no-referrer"
              style={{ width: 168, maxWidth: '100%', height: 'auto' }}
            />
          </a>
        </div>
      </footer>
    </main>
  );
}
