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
}

export interface SecretsScanResult {
  host: string;
  findings: SecretFinding[];
  grade: Grade;
  score: number;
  summary: string;
}

interface SecretRule {
  id: string;
  label: string;
  severity: Severity;
  regex: RegExp;
}

const RULES: SecretRule[] = [
  { id: 'stripe-secret', label: 'Stripe secret key', severity: 'high', regex: /\b[sr]k_live_[A-Za-z0-9]{20,}/g },
  { id: 'aws-key', label: 'AWS access key id', severity: 'high', regex: /\bAKIA[0-9A-Z]{16}\b/g },
  { id: 'github-token', label: 'GitHub token', severity: 'high', regex: /\b(?:ghp|gho|ghs|ghr)_[A-Za-z0-9]{36}\b/g },
  { id: 'github-pat', label: 'GitHub fine-grained token', severity: 'high', regex: /\bgithub_pat_[A-Za-z0-9_]{60,}/g },
  { id: 'anthropic', label: 'Anthropic API key', severity: 'high', regex: /\bsk-ant-[A-Za-z0-9_-]{24,}/g },
  { id: 'openai', label: 'OpenAI API key', severity: 'high', regex: /\bsk-(?:proj-)?[A-Za-z0-9]{40,}\b/g },
  { id: 'private-key', label: 'Private key', severity: 'high', regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g },
  { id: 'google-api', label: 'Google API key (verify it is restricted)', severity: 'medium', regex: /\bAIza[0-9A-Za-z_-]{35}\b/g },
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
  const add = (id: string, label: string, severity: Severity, match: string) => {
    const key = id + ':' + match;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ id, label, severity, redacted: redact(match) });
  };

  for (const rule of RULES) {
    for (const m of text.matchAll(rule.regex)) add(rule.id, rule.label, rule.severity, m[0]);
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

export function gradeSecrets(findings: SecretFinding[], host = ''): SecretsScanResult {
  const high = findings.filter((f) => f.severity === 'high');
  const grade: Grade = high.length ? 'F' : findings.length ? 'C' : 'A';
  const score = high.length ? 8 : findings.length ? 62 : 100;
  return {
    host,
    findings,
    grade,
    score,
    summary: high.length
      ? `${high.length} secret key${high.length === 1 ? '' : 's'} exposed in your frontend code`
      : findings.length
        ? `${findings.length} key${findings.length === 1 ? '' : 's'} worth double-checking`
        : 'No secret keys found in your client code ✅',
  };
}
