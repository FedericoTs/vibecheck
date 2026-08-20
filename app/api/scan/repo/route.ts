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
} from '@/lib/scan/repo';

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
  const findings = analyzeRepoFiles(files);
  const grade = gradeRepo(findings);

  return NextResponse.json({
    ok: true,
    ref: refStr,
    filesScanned: files.length,
    findings,
    grade,
    summary:
      findings.length === 0
        ? `${files.length} source file(s) scanned — no committed secrets or cross-tenant patterns found ✅`
        : `${findings.length} issue(s) across ${files.length} source file(s) ⚠️`,
  } as RepoScanResult);
}
