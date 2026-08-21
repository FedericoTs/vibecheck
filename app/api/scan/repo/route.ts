import { NextResponse } from 'next/server';
import { rateLimitResponse } from '@/lib/rate-limit';
import { UA } from '@/lib/scan/fetch';
import {
  parseRepoUrl,
  selectFiles,
  isFixture,
  analyzeRepoFiles,
  gradeRepo,
  type TreeEntry,
  type RepoScanResult,
  type RepoFinding,
} from '@/lib/scan/repo';
import { lintDockerfile, isDockerfilePath, looksLikeDockerfile } from '@/lib/scan/dockerfile';
import {
  parseNpmLock,
  parsePnpmLock,
  parseYarnLock,
  parsePackageJson,
  parseRequirementsTxt,
  osvBatchBody,
  parseOsvBatch,
  classifyVuln,
  type Dep,
  type DepSeverity,
} from '@/lib/scan/deps';

export const runtime = 'nodejs';
export const maxDuration = 60;

const MAX_FILES = 60;
const MAX_FILE_BYTES = 400_000;
const CONCURRENCY = 8;

/** GitHub API + raw hosts are fixed, so there is no SSRF surface here. */
function gh(path: string): string {
  return `https://api.github.com${path}`;
}

function authHeaders(): Record<string, string> {
  const token = process.env.GITHUB_TOKEN;
  return {
    'user-agent': UA,
    accept: 'application/vnd.github+json',
    ...(token ? { authorization: `Bearer ${token}` } : {}),
  };
}

/**
 * GitHub's rate-limit headers, captured from the last API call.
 *
 * Surfaced in the response because it answers two questions honestly that the
 * scan otherwise answers badly: whether an authenticated token is actually in
 * use (limit 5000 vs 60 — visible from outside without ever exposing the
 * token), and whether a thin result is a clean repo or an exhausted quota.
 * Reporting "we ran out of API budget" is a true statement; silently returning
 * fewer findings is not.
 */
export interface GhRateLimit {
  limit: number;
  remaining: number;
  /** Unix seconds when the window resets. */
  reset: number;
  /** limit > 60 means the token was accepted. */
  authenticated: boolean;
}

let lastRateLimit: GhRateLimit | null = null;

function captureRateLimit(res: Response): void {
  const limit = Number(res.headers.get('x-ratelimit-limit'));
  const remaining = Number(res.headers.get('x-ratelimit-remaining'));
  const reset = Number(res.headers.get('x-ratelimit-reset'));
  if (!Number.isFinite(limit) || limit <= 0) return;
  lastRateLimit = { limit, remaining, reset, authenticated: limit > 60 };
}

async function fetchJson(url: string): Promise<{ status: number; body: unknown }> {
  const res = await fetch(url, { headers: authHeaders(), signal: AbortSignal.timeout(10_000) });
  captureRateLimit(res);
  let body: unknown = null;
  try {
    body = await res.json();
  } catch {
    /* non-JSON */
  }
  return { status: res.status, body };
}

/**
 * The outcome of reading one file. A failure MUST be distinguishable from an
 * empty file.
 *
 * Returning '' for both produced the worst bug in this route: a throttled
 * raw.githubusercontent.com made every fetch look like an empty file, every
 * scanner found nothing, and the report rendered a green dial, a green border
 * and "0 source file(s) scanned, nothing found ✓". A totally failed scan
 * presented as a clean bill of health.
 */
type RawResult =
  | { ok: true; text: string }
  | { ok: false; reason: 'rate_limited' | 'anomaly' | 'timeout' | 'error'; status: number };

/**
 * NB: no Authorization header, deliberately.
 *
 * raw.githubusercontent.com honours Authorization — that is how private-repo
 * raw works — but an invalid, expired or truncated token does NOT degrade to
 * anonymous: GitHub 404s instead, to avoid disclosing existence. Adding a token
 * here would turn every public scan into "0 files, grade A" the moment it went
 * stale. Anonymous is the correct path for public repos.
 */
async function fetchRawResult(owner: string, repo: string, branch: string, path: string): Promise<RawResult> {
  try {
    const res = await fetch(
      `https://raw.githubusercontent.com/${owner}/${repo}/${encodeURIComponent(branch)}/${path.split('/').map(encodeURIComponent).join('/')}`,
      { headers: { 'user-agent': UA }, signal: AbortSignal.timeout(8_000) },
    );
    // A zero-byte 200 is a successful read of an empty file, not a failure.
    if (res.ok) return { ok: true, text: (await res.text()).slice(0, MAX_FILE_BYTES) };
    if (res.status === 429 || res.status === 403) return { ok: false, reason: 'rate_limited', status: res.status };
    // A 404 is an ANOMALY, not absence: the git-tree API just told us this blob
    // exists, so it going missing means something failed on the way.
    if (res.status === 404) return { ok: false, reason: 'anomaly', status: 404 };
    return { ok: false, reason: 'error', status: res.status };
  } catch (e) {
    const timedOut = e instanceof Error && /abort|timeout/i.test(`${e.name} ${e.message}`);
    return { ok: false, reason: timedOut ? 'timeout' : 'error', status: 0 };
  }
}

/** Text-or-empty wrapper, for call sites that only need the content. */
async function fetchRaw(owner: string, repo: string, branch: string, path: string): Promise<string> {
  const r = await fetchRawResult(owner, repo, branch, path);
  return r.ok ? r.text : '';
}

async function mapLimit<T, R>(items: T[], limit: number, fn: (t: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let i = 0;
  await Promise.all(
    Array.from({ length: Math.min(limit, items.length) }, async () => {
      while (i < items.length) {
        const idx = i++;
        out[idx] = await fn(items[idx]);
      }
    }),
  );
  return out;
}

function fail(ref: string, error: string, status = 400): Response {
  // grade 'unknown', never 'A' — an error path must not carry a passing grade
  // even if the client currently gates on ok:false.
  return NextResponse.json({ ok: false, ref, filesScanned: 0, findings: [], grade: 'unknown', summary: error, error } as RepoScanResult, { status });
}

const DEP_MANIFESTS = ['package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', 'package.json', 'requirements.txt'];
const MAX_MANIFEST_BYTES = 6_000_000; // lockfiles carry the whole transitive tree

/** Like fetchRaw but with a big cap, since a truncated lockfile fails to parse. */
async function fetchManifest(owner: string, repo: string, branch: string, path: string): Promise<string> {
  try {
    const res = await fetch(
      `https://raw.githubusercontent.com/${owner}/${repo}/${encodeURIComponent(branch)}/${path.split('/').map(encodeURIComponent).join('/')}`,
      { headers: { 'user-agent': UA }, signal: AbortSignal.timeout(12_000) },
    );
    if (!res.ok) return '';
    return (await res.text()).slice(0, MAX_MANIFEST_BYTES);
  } catch {
    return '';
  }
}
const SEV_RANK: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, unknown: 1 };

/**
 * Ask OSV.dev (free, keyless) which of the repo's exact dependency versions
 * carry a known vulnerability or are outright malicious. Best-effort: any
 * network failure returns no findings rather than a wrong grade.
 */
async function scanDependencies(
  owner: string,
  repo: string,
  branch: string,
  tree: TreeEntry[],
): Promise<{ findings: RepoFinding[]; deps: Dep[]; depsTruncated: number; usingRangeFloor: boolean }> {
  const manifests = tree
    .map((e) => e.path)
    .filter((p) => DEP_MANIFESTS.some((m) => p === m || p.endsWith('/' + m)) && !/node_modules\//.test(p) && !isFixture(p))
    .sort((a, b) => a.split('/').length - b.split('/').length) // root manifests first
    .slice(0, 6);
  if (manifests.length === 0) return { findings: [], deps: [], depsTruncated: 0, usingRangeFloor: false };

  const loaded = await mapLimit(manifests, 4, async (p) => ({ p, content: await fetchManifest(owner, repo, branch, p) }));
  const lockDeps: Dep[] = [];
  const pkgDeps: Dep[] = [];
  const reqDeps: Dep[] = [];
  for (const { p, content } of loaded) {
    if (!content) continue;
    if (p.endsWith('package-lock.json')) lockDeps.push(...parseNpmLock(content));
    else if (p.endsWith('pnpm-lock.yaml')) lockDeps.push(...parsePnpmLock(content));
    else if (p.endsWith('yarn.lock')) lockDeps.push(...parseYarnLock(content));
    else if (p.endsWith('package.json')) pkgDeps.push(...parsePackageJson(content));
    else if (p.endsWith('requirements.txt')) reqDeps.push(...parseRequirementsTxt(content));
  }
  // Prefer the lockfile's exact resolved versions; if it was missing,
  // unparseable or truncated (0 deps), fall back to package.json's declared
  // ranges.
  //
  // That fallback is a GUESS, and it must be labelled as one. cleanVersion
  // takes the floor of a range, so `^8.4.23` is queried as 8.4.23 — which may
  // be a version the user does not have installed at all. Reporting "pkg@8.4.23
  // has a known vulnerability" against a lockfile that actually resolves 8.4.49
  // is a false statement about their app, so range-floor findings are reported
  // and never graded.
  const usingRangeFloor = lockDeps.length === 0 && pkgDeps.length > 0;
  const deps: Dep[] = [...(lockDeps.length ? lockDeps : pkgDeps), ...reqDeps];
  const uniq = new Map<string, Dep>();
  for (const d of deps) uniq.set(`${d.ecosystem}:${d.name}@${d.version}`, d);
  const DEP_CAP = 500;
  const allDeps = [...uniq.values()];
  const list = allDeps.slice(0, DEP_CAP);
  // Truncation must never be silent: a capped SBOM that says nothing about the
  // cap reads as a complete inventory, and the deps beyond it were never queried.
  const depsTruncated = Math.max(0, allDeps.length - list.length);
  if (list.length === 0) return { findings: [], deps: list, depsTruncated, usingRangeFloor: false };

  let batch: unknown;
  try {
    const res = await fetch('https://api.osv.dev/v1/querybatch', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'user-agent': UA },
      body: JSON.stringify(osvBatchBody(list)),
      signal: AbortSignal.timeout(15_000),
    });
    if (!res.ok) return { findings: [], deps: list, depsTruncated, usingRangeFloor };
    batch = await res.json();
  } catch {
    return { findings: [], deps: list, depsTruncated, usingRangeFloor };
  }
  const vulnerable = parseOsvBatch(list, (batch as { results?: Array<{ vulns?: Array<{ id: string }> }> })?.results);
  if (vulnerable.length === 0) return { findings: [], deps: list, depsTruncated, usingRangeFloor };

  // A global budget of 30 detail fetches meant a repo with many advisories had
  // most of them left unclassified — and, before the id-based malware check
  // above, could lose the MALICIOUS label entirely. 150 at concurrency 6 costs
  // ~2s of the 60s budget. Ids are sorted so the truncation is at least stable
  // between runs rather than depending on Set iteration order.
  const ids = [...new Set(vulnerable.flatMap((v) => v.ids))].sort().slice(0, 150);
  const details = new Map<string, ReturnType<typeof classifyVuln>>();
  await mapLimit(ids, 6, async (id) => {
    try {
      const r = await fetch(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`, { headers: { 'user-agent': UA }, signal: AbortSignal.timeout(8_000) });
      if (r.ok) details.set(id, classifyVuln(await r.json()));
    } catch {
      /* skip this id */
    }
  });

  const findings: RepoFinding[] = [];
  for (const { dep, ids: vids } of vulnerable) {
    const classified = vids.map((i) => details.get(i)).filter((c): c is ReturnType<typeof classifyVuln> => !!c);
    const worst = [...classified].sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity])[0];
    // A MAL- id IS a malicious-package advisory by definition, and the id is
    // already in hand from querybatch — so malware is established WITHOUT a
    // detail fetch. Previously, if the detail budget ran out before reaching a
    // Shai-Hulud advisory, the MALICIOUS label was silently dropped.
    const malwareFromId = vids.some((i) => /^MAL-/i.test(i));
    const malware = malwareFromId || classified.some((c) => c.malware);
    const summary = worst?.summary && worst.summary !== vids[0] ? `: ${worst.summary.slice(0, 100)}` : '';
    // Severity is only claimed where it was actually established. With no
    // detail fetched, saying 'medium' invents a rating; 'unknown' is the truth.
    const severity: DepSeverity = malware ? 'critical' : (worst?.severity ?? 'unknown');
    const unresolved = vids.length - classified.length;
    findings.push({
      kind: 'dependency',
      path: `${dep.name}@${dep.version}`,
      label: malware
        ? `MALICIOUS package: ${dep.name}@${dep.version}`
        : usingRangeFloor && dep.ecosystem === 'npm'
          ? `${dep.name}: the lowest version your package.json allows (${dep.version}) has a known vulnerability`
          : `${dep.name}@${dep.version} has a known vulnerability`,
      severity: severity === 'unknown' || severity === 'low' ? 'medium' : severity,
      detail:
        `${vids.length} advisor${vids.length === 1 ? 'y' : 'ies'} (${vids.slice(0, 2).join(', ')})${summary}` +
        (severity === 'unknown'
          ? ` — severity not established (details fetched for ${classified.length} of ${vids.length})`
          : unresolved > 0
            ? ` — ${unresolved} advisor${unresolved === 1 ? 'y' : 'ies'} not detailed`
            : ''),
      // Neither an unestablished severity nor a guessed version may move the
      // grade.
      ...(severity === 'unknown' || (usingRangeFloor && dep.ecosystem === 'npm') ? { graded: false } : {}),
    });
  }
  // Worst first, and capped so a repo with dozens of stale deps stays readable.
  return {
    findings: findings.sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity]).slice(0, 40),
    deps: list,
    depsTruncated,
    usingRangeFloor,
  };
}

/** Lint any Dockerfiles in the repo (only the subset that containerises has one). */
async function scanDockerfiles(owner: string, repo: string, branch: string, tree: TreeEntry[]): Promise<RepoFinding[]> {
  const paths = tree
    .map((e) => e.path)
    .filter((p) => isDockerfilePath(p) && !/node_modules\//.test(p) && !isFixture(p))
    .slice(0, 4);
  if (paths.length === 0) return [];
  const loaded = await mapLimit(paths, 4, async (p) => ({ p, content: await fetchRaw(owner, repo, branch, p) }));
  const out: RepoFinding[] = [];
  for (const { p, content } of loaded) {
    // Name says Dockerfile AND content proves it. Without the second gate a
    // fixture or a doc that merely looks the part gets linted as a container.
    if (!content || !looksLikeDockerfile(content)) continue;
    for (const f of lintDockerfile(content)) {
      out.push({ kind: 'dockerfile', path: p, label: `${f.label} (${p})`, severity: f.severity, detail: f.detail });
    }
  }
  return out;
}

export async function POST(request: Request): Promise<Response> {
  const limited = rateLimitResponse(request.headers);
  if (limited) return limited;

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: 'Invalid request body' }, { status: 400 });
  }
  const raw = typeof (body as { repo?: unknown })?.repo === 'string' ? (body as { repo: string }).repo : '';
  const ref = parseRepoUrl(raw);
  if (!ref) return fail(raw, 'That does not look like a GitHub repository (try github.com/owner/repo).');
  const refStr = `${ref.owner}/${ref.repo}`;

  // 1) repo metadata — confirms it exists and is PUBLIC.
  const meta = await fetchJson(gh(`/repos/${ref.owner}/${ref.repo}`));
  if (meta.status === 404) return fail(refStr, 'Repository not found, or it is private. This tool scans public repos only — for a private repo, run tenant-guard in your CI.', 404);
  if (meta.status === 403) return fail(refStr, 'GitHub rate limit reached. Try again shortly.', 429);
  if (meta.status !== 200) return fail(refStr, `Could not reach GitHub (HTTP ${meta.status}).`, 502);
  const m = meta.body as { default_branch?: string; private?: boolean };
  if (m.private) return fail(refStr, 'That repository is private — this tool scans public repos only.', 400);
  const branch = m.default_branch ?? 'main';

  // 2) file tree
  const treeRes = await fetchJson(gh(`/repos/${ref.owner}/${ref.repo}/git/trees/${encodeURIComponent(branch)}?recursive=1`));
  if (treeRes.status !== 200) return fail(refStr, 'Could not read the repository file tree.', 502);
  const tree = ((treeRes.body as { tree?: TreeEntry[] })?.tree ?? []).filter((e) => e && e.type === 'blob');
  const paths = selectFiles(tree, MAX_FILES);
  if (paths.length === 0)
    return NextResponse.json({
      ok: true,
      ref: refStr,
      filesScanned: 0,
      findings: [],
      grade: 'unknown',
      summary: 'No scannable source files found in this repository.',
    } as RepoScanResult);

  // 3) fetch contents + analyse
  const reads = await mapLimit(paths, CONCURRENCY, async (p) => ({ path: p, result: await fetchRawResult(ref.owner, ref.repo, branch, p) }));
  const files = reads
    .filter((r): r is { path: string; result: { ok: true; text: string } } => r.result.ok)
    .map((r) => ({ path: r.path, content: r.result.text }));

  // Count what FAILED, never what came back empty. A zero-byte file is a
  // successful read — empty __init__.py files are idiomatic and ubiquitous in
  // Python packages, so gating on "how many files had content" would grade a
  // perfectly good Django or FastAPI repo as unreadable.
  const failures = reads.filter((r) => !r.result.ok).map((r) => r.result as Extract<RawResult, { ok: false }>);
  const rateLimited = failures.filter((f) => f.reason === 'rate_limited' || f.reason === 'anomaly').length;
  const unreadable = failures.length;
  const [sourceFindings, depResult, dockerFindings] = await Promise.all([
    Promise.resolve(analyzeRepoFiles(files)),
    scanDependencies(ref.owner, ref.repo, branch, tree),
    scanDockerfiles(ref.owner, ref.repo, branch, tree),
  ]);
  const findings = [...sourceFindings, ...dockerFindings, ...depResult.findings];
  const depFindings = depResult.findings;

  // If we could not actually read the repo, say so. Grading a scan that fetched
  // nothing is the false pass this whole change exists to prevent.
  const tooManyFailed = rateLimited > 0 || unreadable > paths.length * 0.2;
  const grade = tooManyFailed ? 'unknown' : gradeRepo(findings);

  return NextResponse.json({
    ok: true,
    ref: refStr,
    filesScanned: files.length,
    findings,
    dependencies: depResult.deps,
    rateLimit: lastRateLimit,
    unreadableFiles: unreadable,
    filesSelected: paths.length,
    depsTruncated: depResult.depsTruncated,
    dependencyVersionsInferred: depResult.usingRangeFloor,
    grade,
    summary: tooManyFailed
      ? `GitHub would not serve ${unreadable} of ${paths.length} files, so this scan is incomplete — no grade. Try again in a few minutes.`
      : findings.length === 0
        ? // Never claim a subsystem was "scanned" when it was not. A Go or Rust
          // repo has no manifest we parse, and saying "dependencies scanned"
          // there asserts work that never happened.
          `${files.length} source file(s) scanned${depResult.deps.length > 0 ? ` · ${depResult.deps.length} dependencies checked` : ' · no supported dependency manifest found, so dependencies were NOT checked'} — nothing found ✅`
        : `${findings.length} issue(s) found${depFindings.length ? ` (${depFindings.length} in dependencies)` : ''} ⚠️`,
  } as RepoScanResult);
}
