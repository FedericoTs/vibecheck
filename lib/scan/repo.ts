import { findSecrets } from './secrets';
import type { Dep } from './deps';

/**
 * Public-repository analysis — the source-level half of the picture a URL scan
 * cannot reach.
 *
 * A live-app scan reads what a stranger sees. Some of the worst vibe-coded bugs
 * live in the source instead: a committed .env, a hard-coded key in server code
 * that never reaches the bundle, and above all the cross-tenant IDOR — an
 * authenticated API route that filters a query by a bare id and never scopes it
 * to the caller's organisation, so any signed-in user can read another tenant's
 * rows. That last one is exactly what tenant-guard is built to catch, and it is
 * the check we are genuinely best at.
 *
 * PUBLIC repos only: the code is already public, so this needs no permissions
 * and stores nothing — the same trust model as the rest of the tool. Private
 * repos belong in tenant-guard's CI install, which also runs the runtime proof.
 *
 * The pure detectors below are I/O-free and unit-tested; the network fetch is a
 * thin layer over the GitHub API.
 */

export interface RepoRef {
  owner: string;
  repo: string;
}

/** Pull owner/repo out of a github.com URL (or an "owner/repo" shorthand). */
export function parseRepoUrl(input: string): RepoRef | null {
  const raw = (input ?? '').trim();
  if (!raw) return null;
  const m =
    raw.match(/github\.com[/:]([A-Za-z0-9._-]+)\/([A-Za-z0-9._-]+?)(?:\.git)?(?:[/#?].*)?$/i) ??
    raw.match(/^([A-Za-z0-9._-]+)\/([A-Za-z0-9._-]+)$/);
  if (!m) return null;
  return { owner: m[1], repo: m[2].replace(/\.git$/i, '') };
}

// ── file selection ───────────────────────────────────────────────────

/** Source we scan for secrets. Includes any .env variant (.env.local, .env.production). */
const SCANNABLE = /\.(ts|tsx|js|jsx|mjs|cjs|py|rb|go|php|java|json|ya?ml|toml|sql|sh)$/i;
const ENV_FILE = /(^|\/)\.env(\.[A-Za-z0-9_-]+)?$/i;
const scannable = (p: string): boolean => SCANNABLE.test(p) || ENV_FILE.test(p);
/** Never worth reading: dependencies, lockfiles, build output, binaries. */
const IGNORED = /(^|\/)(node_modules|\.next|dist|build|vendor|\.git|coverage|__pycache__)\//i;
const IGNORED_FILE = /(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|\.min\.(js|css))$/i;
/**
 * Tests, fixtures, examples and demos are DELIBERATE — they carry fake secrets
 * (AKIA...EXAMPLE) and teaching vulnerabilities on purpose. Scanning them
 * produced exactly that false positive live (our own test suite; tenant-guard's
 * leaky demo), so they are excluded. Templates like .env.example are placeholders.
 */
const TEST_OR_EXAMPLE = /(^|\/)(__tests__|__mocks__|tests?|specs?|fixtures?|examples?|demos?|mocks?|e2e|cypress|playwright|\.storybook)\//i;
const TEST_OR_EXAMPLE_FILE = /\.(test|spec|stories|mock|fixture|cy|e2e)\.[a-z]+$|\.(example|sample|template)$/i;
export const isFixture = (p: string): boolean => TEST_OR_EXAMPLE.test('/' + p) || TEST_OR_EXAMPLE_FILE.test(p);

export interface TreeEntry {
  path: string;
  type: string;
  size?: number;
}

/** Choose the files worth fetching from a repo tree, newest-relevant first, capped. */
export function selectFiles(tree: TreeEntry[], max = 60): string[] {
  const files = tree
    .filter((e) => e.type === 'blob')
    .map((e) => e.path)
    .filter((p) => scannable(p) && !IGNORED.test('/' + p) && !IGNORED_FILE.test(p) && !isFixture(p));
  // Prioritise the files that carry the two findings we care about most.
  const priority = (p: string): number => {
    if (/(^|\/)\.env/i.test(p)) return 0; // committed secrets
    if (isApiRouteFile(p)) return 1; // cross-tenant IDOR
    if (/(^|\/)(config|settings|constants|secrets)\./i.test(p)) return 2;
    if (/\.sql$/i.test(p)) return 3;
    return 4;
  };
  return files.sort((a, b) => priority(a) - priority(b)).slice(0, max);
}

// ── cross-tenant IDOR (the tenant-guard shape) ───────────────────────

/** An API route file, across the common frameworks. */
export function isApiRouteFile(path: string): boolean {
  return /(^|\/)(app|src\/app|pages|src\/pages)\/api\/.+\.(t|j)sx?$/i.test(path) || /(^|\/)api\/.+\.(t|j)sx?$/i.test(path);
}

// The bug is a CONJUNCTION — each part alone is fine. Encoding the shape, not a
// keyword, is what keeps tenant-guard false-positive-free.
const AUTH_SIGNAL = /withApiAuth|requireAuth|getServerSession|auth\.getUser|supabase\.auth|getUser\s*\(|currentUser\s*\(|verifyAuth|getSession\s*\(/i;
const BARE_ID_FILTER =
  /\.eq\(\s*['"`]id['"`]|\.match\(\s*\{\s*id\b|where:\s*\{\s*id\b|eq\(\s*\w+\.id\s*,|findUnique\(\s*\{\s*where:\s*\{\s*id\b|\bWHERE\s+id\s*=/i;
const TENANT_COLUMN = /organization_?id|organizationId|tenant_?id|tenantId|account_?id|workspace_?id|org_?id/i;

export interface ScopingFinding {
  path: string;
  detail: string;
}

/** The route-org-scoping shape: authenticated, filters by bare id, never scopes to a tenant. */
export function detectCrossTenant(path: string, content: string): ScopingFinding | null {
  if (!isApiRouteFile(path)) return null;
  const authed = AUTH_SIGNAL.test(content);
  const bareId = BARE_ID_FILTER.test(content);
  const scoped = TENANT_COLUMN.test(content);
  if (authed && bareId && !scoped) {
    return {
      path,
      detail:
        'authenticated, and filters a query by a bare id without scoping it to the caller’s organisation — any signed-in user may be able to read another tenant’s rows',
    };
  }
  return null;
}

// ── the scan ─────────────────────────────────────────────────────────

export type RepoFindingKind = 'secret' | 'cross-tenant' | 'dependency' | 'dockerfile';

export interface RepoFinding {
  kind: RepoFindingKind;
  path: string;
  label: string;
  severity: 'critical' | 'high' | 'medium';
  detail: string;
}

export interface RepoScanResult {
  ok: boolean;
  ref: string;
  filesScanned: number;
  findings: RepoFinding[];
  /** Full resolved dependency inventory — powers the downloadable SBOM. */
  dependencies?: Dep[];
  /**
   * GitHub's own rate-limit accounting from the last API call. `authenticated`
   * separates a token-backed 5,000/hr budget from the anonymous 60/hr one — the
   * only way to confirm from outside that a deployment is really sending a
   * token, without ever exposing the token itself.
   */
  rateLimit?: { limit: number; remaining: number; reset: number; authenticated: boolean } | null;
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  summary: string;
  error?: string;
}

/** Turn a set of {path, content} into findings. Pure — the network layer feeds it. */
export function analyzeRepoFiles(files: Array<{ path: string; content: string }>): RepoFinding[] {
  const findings: RepoFinding[] = [];
  const seen = new Set<string>();
  for (const { path, content } of files) {
    // committed secrets
    for (const s of findSecrets(content)) {
      const key = `s:${path}:${s.id}:${s.redacted}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const committedEnv = /(^|\/)\.env/i.test(path);
      findings.push({
        kind: 'secret',
        path,
        label: committedEnv ? `${s.label} committed in ${path.split('/').pop()}` : `${s.label} in source (${path})`,
        severity: 'critical',
        detail: s.redacted,
      });
    }
    // cross-tenant IDOR
    const ct = detectCrossTenant(path, content);
    if (ct) {
      findings.push({ kind: 'cross-tenant', path, label: `Possible cross-tenant access (${path})`, severity: 'high', detail: ct.detail });
    }
  }
  return findings;
}

export function gradeRepo(findings: RepoFinding[]): RepoScanResult['grade'] {
  const crit = findings.filter((f) => f.severity === 'critical').length;
  const high = findings.filter((f) => f.severity === 'high').length;
  if (crit > 0) return 'F';
  if (high >= 2) return 'F';
  if (high === 1) return 'D';
  return 'A';
}
