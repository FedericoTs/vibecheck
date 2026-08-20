import { NextResponse } from 'next/server';
import { rateLimitResponse } from '@/lib/rate-limit';
import { UA } from '@/lib/scan/fetch';
import {
  parseRepoUrl,
  selectFiles,
  analyzeRepoFiles,
  gradeRepo,
  type TreeEntry,
  type RepoScanResult,
  type RepoFinding,
} from '@/lib/scan/repo';
import { lintDockerfile } from '@/lib/scan/dockerfile';
import {
  parseNpmLock,
  parsePackageJson,
  parseRequirementsTxt,
  osvBatchBody,
  parseOsvBatch,
  classifyVuln,
  type Dep,
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

async function fetchJson(url: string): Promise<{ status: number; body: unknown }> {
  const res = await fetch(url, { headers: authHeaders(), signal: AbortSignal.timeout(10_000) });
  let body: unknown = null;
  try {
    body = await res.json();
  } catch {
    /* non-JSON */
  }
  return { status: res.status, body };
}

async function fetchRaw(owner: string, repo: string, branch: string, path: string): Promise<string> {
  try {
    const res = await fetch(
      `https://raw.githubusercontent.com/${owner}/${repo}/${encodeURIComponent(branch)}/${path.split('/').map(encodeURIComponent).join('/')}`,
      { headers: { 'user-agent': UA }, signal: AbortSignal.timeout(8_000) },
    );
    if (!res.ok) return '';
    return (await res.text()).slice(0, MAX_FILE_BYTES);
  } catch {
    return '';
  }
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
  return NextResponse.json({ ok: false, ref, filesScanned: 0, findings: [], grade: 'A', summary: error, error } as RepoScanResult, { status });
}

const DEP_MANIFESTS = ['package-lock.json', 'package.json', 'requirements.txt'];
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
const SEV_RANK = { critical: 3, high: 2, medium: 1 } as const;

/**
 * Ask OSV.dev (free, keyless) which of the repo's exact dependency versions
 * carry a known vulnerability or are outright malicious. Best-effort: any
 * network failure returns no findings rather than a wrong grade.
 */
async function scanDependencies(owner: string, repo: string, branch: string, tree: TreeEntry[]): Promise<{ findings: RepoFinding[]; deps: Dep[] }> {
  const manifests = tree
    .map((e) => e.path)
    .filter((p) => DEP_MANIFESTS.some((m) => p === m || p.endsWith('/' + m)) && !/node_modules\//.test(p))
    .sort((a, b) => a.split('/').length - b.split('/').length) // root manifests first
    .slice(0, 6);
  if (manifests.length === 0) return { findings: [], deps: [] };

  const loaded = await mapLimit(manifests, 4, async (p) => ({ p, content: await fetchManifest(owner, repo, branch, p) }));
  const lockDeps: Dep[] = [];
  const pkgDeps: Dep[] = [];
  const reqDeps: Dep[] = [];
  for (const { p, content } of loaded) {
    if (!content) continue;
    if (p.endsWith('package-lock.json')) lockDeps.push(...parseNpmLock(content));
    else if (p.endsWith('package.json')) pkgDeps.push(...parsePackageJson(content));
    else if (p.endsWith('requirements.txt')) reqDeps.push(...parseRequirementsTxt(content));
  }
  // Prefer the lockfile's exact resolved versions; if it was missing, unparseable
  // or truncated (0 deps), fall back to package.json's declared ranges.
  const deps: Dep[] = [...(lockDeps.length ? lockDeps : pkgDeps), ...reqDeps];
  const uniq = new Map<string, Dep>();
  for (const d of deps) uniq.set(`${d.ecosystem}:${d.name}@${d.version}`, d);
  const list = [...uniq.values()].slice(0, 500);
  if (list.length === 0) return { findings: [], deps: list };

  let batch: unknown;
  try {
    const res = await fetch('https://api.osv.dev/v1/querybatch', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'user-agent': UA },
      body: JSON.stringify(osvBatchBody(list)),
      signal: AbortSignal.timeout(15_000),
    });
    if (!res.ok) return { findings: [], deps: list };
    batch = await res.json();
  } catch {
    return { findings: [], deps: list };
  }
  const vulnerable = parseOsvBatch(list, (batch as { results?: Array<{ vulns?: Array<{ id: string }> }> })?.results);
  if (vulnerable.length === 0) return { findings: [], deps: list };

  const ids = [...new Set(vulnerable.flatMap((v) => v.ids))].slice(0, 30);
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
    const malware = classified.some((c) => c.malware);
    const summary = worst?.summary && worst.summary !== vids[0] ? `: ${worst.summary.slice(0, 100)}` : '';
    findings.push({
      kind: 'dependency',
      path: `${dep.name}@${dep.version}`,
      label: malware
        ? `MALICIOUS package: ${dep.name}@${dep.version}`
        : `${dep.name}@${dep.version} has a known vulnerability`,
      severity: worst?.severity ?? 'medium',
      detail: `${vids.length} advisor${vids.length === 1 ? 'y' : 'ies'} (${vids.slice(0, 2).join(', ')})${summary}`,
    });
  }
  // Worst first, and capped so a repo with dozens of stale deps stays readable.
  return { findings: findings.sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity]).slice(0, 40), deps: list };
}

/** Lint any Dockerfiles in the repo (only the subset that containerises has one). */
async function scanDockerfiles(owner: string, repo: string, branch: string, tree: TreeEntry[]): Promise<RepoFinding[]> {
  const paths = tree
    .map((e) => e.path)
    .filter((p) => /(^|\/)Dockerfile(\.[\w.-]+)?$/i.test(p) && !/node_modules\//.test(p))
    .slice(0, 4);
  if (paths.length === 0) return [];
  const loaded = await mapLimit(paths, 4, async (p) => ({ p, content: await fetchRaw(owner, repo, branch, p) }));
  const out: RepoFinding[] = [];
  for (const { p, content } of loaded) {
    if (!content) continue;
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
  if (paths.length === 0) return NextResponse.json({ ok: true, ref: refStr, filesScanned: 0, findings: [], grade: 'A', summary: 'No scannable source files found.' } as RepoScanResult);

  // 3) fetch contents + analyse
  const files = (await mapLimit(paths, CONCURRENCY, async (p) => ({ path: p, content: await fetchRaw(ref.owner, ref.repo, branch, p) }))).filter(
    (f) => f.content.length > 0,
  );
  const [sourceFindings, depResult, dockerFindings] = await Promise.all([
    Promise.resolve(analyzeRepoFiles(files)),
    scanDependencies(ref.owner, ref.repo, branch, tree),
    scanDockerfiles(ref.owner, ref.repo, branch, tree),
  ]);
  const findings = [...sourceFindings, ...dockerFindings, ...depResult.findings];
  const depFindings = depResult.findings;
  const grade = gradeRepo(findings);

  return NextResponse.json({
    ok: true,
    ref: refStr,
    filesScanned: files.length,
    findings,
    dependencies: depResult.deps,
    grade,
    summary:
      findings.length === 0
        ? `${files.length} source file(s) + dependencies scanned — nothing found ✅`
        : `${findings.length} issue(s) found${depFindings.length ? ` (${depFindings.length} in dependencies)` : ''} ⚠️`,
  } as RepoScanResult);
}
