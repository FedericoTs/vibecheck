import type { Grade } from './types';

/**
 * Secret-scanner for client-side code (the HTML + same-origin JS bundles).
 * AI-built apps routinely ship server secrets to the browser — a Supabase
 * `service_role` key, a Stripe secret key, an OpenAI key. These are readable by
 * anyone who opens devtools.
 *
 * Precision is everything: a false "your key is exposed" destroys trust. So the
 * patterns are tight, publishable keys (Stripe `pk_`, the Supabase `anon` JWT)
 * are deliberately NOT flagged, and JWTs are decoded to check the role claim so
 * only a real `service_role` key trips it.
 */

export type Severity = 'high' | 'medium';

export interface SecretFinding {
  id: string;
  label: string;
  severity: Severity;
  redacted: string;
  /**
   * True when a connection string points somewhere unreachable from the
   * internet — localhost, a private range, a docker-compose service name.
   * Those credentials are the framework default and are not readable by
   * anyone who is not already on the box, so they are reported, never graded.
   */
  local?: boolean;
  /** Found on a commented-out line — reported, never graded. */
  commented?: boolean;
}

/**
 * Hosts that are not reachable from the internet.
 *
 * Deliberately keyed on the HOST alone. A well-known credential pair is NOT a
 * safe suppressor: the same throwaway credential pair pointed at a real
 * production host is a genuine and serious leak, and filtering on the password
 * would hide it. (Deliberately not spelled out as a literal URL here — this
 * file is scanned by its own rules.)
 * A bare single-label host (`db`, `postgres`, `mysql`) is a docker-compose
 * service name, which is equally unreachable.
 */
const LOCAL_DB_HOST =
  /^(localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|\[?::1\]?|host\.docker\.internal|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|[a-z0-9_-]+|.*\.(local|internal|test|localhost))$/i;

/**
 * Is the match on a commented-out line?
 *
 * A placeholder in a comment — including the ones in this very file — is not a
 * live credential, and grading it critical is how a scanner accuses a codebase
 * of a leak it does not have. Reported, never graded: it IS still in git
 * history, so if the value was ever real it should be rotated.
 *
 * Deliberately looks only at the text BEFORE the match on its line. Stripping
 * `//` comments outright would decapitate `postgres://…` and blind the
 * connection-string rule entirely.
 */
export function isCommentedLine(text: string, index: number): boolean {
  const lineStart = text.lastIndexOf('\n', index) + 1;
  const prefix = text.slice(lineStart, index).trim();
  return /^(\/\/|\*|\/\*|#|--)/.test(prefix);
}

/** Does this connection string point at a non-routable host? */
export function isLocalDbUrl(match: string): boolean {
  const at = match.lastIndexOf('@');
  if (at === -1) return false;
  const host = match.slice(at + 1).split(/[/:?]/)[0];
  return LOCAL_DB_HOST.test(host);
}

export interface SecretsScanResult {
  host: string;
  findings: SecretFinding[];
  /** publicly served .js.map files — these republish your original source code. */
  sourceMaps?: {
    exposed: string[];
    /**
     * The map URLs themselves, so a finding can carry the request that proves
     * it. Excludes inline data: URIs, which cannot be fetched and must never
     * be rendered as a command.
     */
    mapUrls?: string[];
    checked: boolean;
    /** Chunks that referenced a map, whether or not it actually resolved. */
    annotated?: number;
    /** Referenced a map that did NOT resolve — reported honestly, never as proof of safety. */
    unresolved?: number;
    /** Original app files (not dependencies) the resolved maps reconstruct. */
    firstPartyFiles?: number;
    /** A few recovered paths, as evidence. Never file content. */
    sample?: string[];
  };
  /** advisory: browser-side Google/Firebase keys, which are public by design. */
  publicGoogleKeys?: number;
  grade: Grade;
  score: number;
  summary: string;
}

/**
 * Browser-side Google/Firebase API keys. These are meant to be public, so this
 * is advisory only — the actionable question is whether they are referrer-restricted.
 */
export function countPublicGoogleKeys(text: string): number {
  return new Set([...text.matchAll(/\bAIza[0-9A-Za-z_-]{35}\b/g)].map((m) => m[0])).size;
}

/**
 * The ORIGINAL source a source map republishes, from its `sourcesContent` array.
 * Minification frequently drops or mangles string literals, so a key that is
 * invisible in the shipped bundle can be plainly readable here — which is
 * exactly why a published .map is worth scanning, not just flagging.
 */
export function sourcesFromMap(body: string): string {
  try {
    const map = JSON.parse(body) as { sourcesContent?: unknown };
    if (Array.isArray(map.sourcesContent)) {
      return map.sourcesContent.filter((s): s is string => typeof s === 'string').join('\n');
    }
  } catch {
    /* not a parseable map */
  }
  return '';
}

/** Is this response body an actual source map (not an SPA HTML fallback)? */
export function isSourceMap(status: number, body: string): boolean {
  if (status !== 200) return false;
  const head = body.slice(0, 400);
  if (/^\s*<(!doctype|html)/i.test(head)) return false;
  return /"version"\s*:\s*3/.test(head) && /"sources"\s*:\s*\[/.test(head.length < 400 ? body.slice(0, 4000) : body.slice(0, 4000));
}

interface SecretRule {
  id: string;
  label: string;
  severity: Severity;
  regex: RegExp;
}

const RULES: SecretRule[] = [
  // Supabase's current privileged key format (the service_role successor).
  // `sb_publishable_…` is deliberately absent — that one is meant to be public.
  { id: 'supabase-secret', label: 'Supabase secret key (bypasses all RLS)', severity: 'high', regex: /\bsb_secret_[A-Za-z0-9_-]{16,}/g },
  { id: 'stripe-secret', label: 'Stripe secret key', severity: 'high', regex: /\b[sr]k_live_[A-Za-z0-9]{20,}/g },
  { id: 'aws-key', label: 'AWS access key id', severity: 'high', regex: /\bAKIA[0-9A-Z]{16}\b/g },
  { id: 'github-token', label: 'GitHub token', severity: 'high', regex: /\b(?:ghp|gho|ghs|ghr)_[A-Za-z0-9]{36}\b/g },
  { id: 'github-pat', label: 'GitHub fine-grained token', severity: 'high', regex: /\bgithub_pat_[A-Za-z0-9_]{60,}/g },
  { id: 'anthropic', label: 'Anthropic API key', severity: 'high', regex: /\bsk-ant-[A-Za-z0-9_-]{24,}/g },
  { id: 'openai', label: 'OpenAI API key', severity: 'high', regex: /\bsk-(?:proj-)?[A-Za-z0-9]{40,}\b/g },
  { id: 'private-key', label: 'Private key', severity: 'high', regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g },
  // NB: browser-side Google/Firebase `AIza…` keys are deliberately NOT here.
  // They are public by design (secured by HTTP-referrer restrictions, not
  // secrecy), so flagging them would give every Firebase or Maps app a false
  // alarm. They are surfaced as advisory information instead — see
  // countPublicGoogleKeys.
  { id: 'slack-token', label: 'Slack token', severity: 'high', regex: /\bxox[baprs]-[A-Za-z0-9-]{10,}/g },
  { id: 'slack-webhook', label: 'Slack webhook URL', severity: 'high', regex: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/]{20,}/g },
  { id: 'sendgrid', label: 'SendGrid API key', severity: 'high', regex: /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}/g },
  { id: 'twilio', label: 'Twilio account SID', severity: 'high', regex: /\bAC[0-9a-f]{32}\b/g },
  { id: 'mailgun', label: 'Mailgun API key', severity: 'high', regex: /\bkey-[0-9a-f]{32}\b/g },
  { id: 'npm-token', label: 'npm access token', severity: 'high', regex: /\bnpm_[A-Za-z0-9]{36}\b/g },
  { id: 'openai-legacy', label: 'OpenAI project key', severity: 'high', regex: /\bsk-svcacct-[A-Za-z0-9_-]{20,}/g },
  { id: 'jwt-secret', label: 'Hard-coded JWT/session secret', severity: 'high', regex: /(?:jwt|session|cookie)[_-]?secret["'`\s:=]{1,6}["'`][A-Za-z0-9+/_-]{16,}["'`]/gi },
  // user:password@host — the @ with credentials is what makes it a real leak
  // (a bare postgres://localhost:5432/dev has no credentials and must not match).
  { id: 'db-url', label: 'Database connection string', severity: 'high', regex: /\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?):\/\/[^\s"'`<>:@/]+:[^\s"'`<>@/]+@[^\s"'`<>/]+/g },
];

// A JWT (Supabase keys are JWTs). We decode the payload to read the role claim.
const JWT = /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g;

export function redact(s: string): string {
  if (s.length <= 12) return s.slice(0, 3) + '…';
  return s.slice(0, 7) + '…' + s.slice(-4);
}

/** Decode a JWT payload's `role` claim, or null. Portable (atob), no Buffer. */
export function jwtRole(token: string): string | null {
  const parts = token.split('.');
  if (parts.length < 2) return null;
  try {
    let b = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    b += '='.repeat((4 - (b.length % 4)) % 4);
    const json = JSON.parse(atob(b));
    return typeof json.role === 'string' ? json.role : null;
  } catch {
    return null;
  }
}

/** Find exposed secrets in a blob of client code. Pure, deduped. */
export function findSecrets(text: string): SecretFinding[] {
  const seen = new Set<string>();
  const out: SecretFinding[] = [];
  const add = (id: string, label: string, severity: Severity, match: string, index = -1) => {
    const key = id + ':' + match;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({
      id,
      label,
      severity,
      redacted: redact(match),
      ...(id === 'db-url' && isLocalDbUrl(match) ? { local: true } : {}),
      ...(index >= 0 && isCommentedLine(text, index) ? { commented: true } : {}),
    });
  };

  for (const rule of RULES) {
    for (const m of text.matchAll(rule.regex)) add(rule.id, rule.label, rule.severity, m[0], m.index ?? -1);
  }
  // Supabase service_role key: a JWT whose role claim is service_role.
  // The anon / authenticated keys are meant to be public — never flag them.
  for (const m of text.matchAll(JWT)) {
    if (jwtRole(m[0]) === 'service_role') {
      add('supabase-service-role', 'Supabase service_role key (bypasses all RLS)', 'high', m[0]);
    }
  }
  return out;
}

/**
 * Whether a finding may move the grade at all.
 *
 * A connection string pointing at localhost, a private range, or a
 * docker-compose service name is not readable by anyone who is not already on
 * the box. It is the framework default, it is in a million tutorials, and
 * grading it is a false accusation — repo mode has said exactly that since it
 * shipped ("points at a local or private host, so it is not reachable from the
 * internet. Reported, not graded."). The URL and mobile paths never got the
 * same treatment, so a localhost DSN recovered from a source map scored an F.
 */
export function isGradedSecret(f: SecretFinding): boolean {
  return f.local !== true;
}

/**
 * Whether a finding is a hard failure rather than something to double-check.
 *
 * `commented` deliberately does NOT get repo mode's free pass. There, the
 * argument is about git history. Here the bytes are being SERVED: a real key on
 * a commented-out line in a published source map is readable by anyone who
 * fetches it, and commenting it out in the editor did not un-publish it. But we
 * cannot tell a real key from a placeholder someone commented out, so it stops
 * being an F and becomes a C — reported firmly, without the accusation.
 */
export function isHardSecret(f: SecretFinding): boolean {
  return isGradedSecret(f) && f.severity === 'high' && f.commented !== true;
}

export function gradeSecrets(findings: SecretFinding[], host = ''): SecretsScanResult {
  const hard = findings.filter(isHardSecret);
  const soft = findings.filter((f) => isGradedSecret(f) && !isHardSecret(f));
  const grade: Grade = hard.length ? 'F' : soft.length ? 'C' : 'A';
  const score = hard.length ? 8 : soft.length ? 62 : 100;
  return {
    host,
    findings,
    grade,
    score,
    summary: hard.length
      ? `${hard.length} secret key${hard.length === 1 ? '' : 's'} exposed in your frontend code`
      : soft.length
        ? `${soft.length} key${soft.length === 1 ? '' : 's'} worth double-checking`
        : findings.length
          ? // Everything we found was unreachable from the internet. Say so
            // rather than printing a bare tick, which would hide the finding.
            `No usable secrets — ${findings.length} local-only credential${findings.length === 1 ? '' : 's'} reported below`
          : 'No secret keys found in your client code ✅',
  };
}
