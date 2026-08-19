import type { Grade } from './types';
import { scoreToGrade } from './grade';

/**
 * Email spoofing protection (SPF / DMARC / MX).
 *
 * If a domain publishes no SPF and no DMARC, anyone on the internet can send
 * mail that appears to come from it — password-reset lookalikes, invoices,
 * phishing aimed at the app's own users. It costs two DNS records to fix and
 * essentially no AI-generated project ever sets them, because the generator only
 * writes application code and never touches DNS.
 *
 * Pure classification here; the DNS lookups happen in the route via Node's
 * resolver (no API, no key, no cost).
 */

export interface EmailAuthCheck {
  key: string;
  label: string;
  pass: boolean;
  severity: 'high' | 'medium' | 'low';
  detail?: string;
}

export interface EmailAuthResult {
  host: string;
  checks: EmailAuthCheck[];
  failed: EmailAuthCheck[];
  grade: Grade;
  score: number;
  summary: string;
}

export interface DnsFacts {
  /** all TXT records at the domain apex, flattened. */
  txt: string[];
  /** TXT records at _dmarc.<domain>. */
  dmarcTxt: string[];
  /** whether the domain has MX records (i.e. actually receives mail). */
  hasMx: boolean;
}

export function findSpf(txt: string[]): string | null {
  return txt.find((t) => /^v=spf1\b/i.test(t.trim())) ?? null;
}

export function findDmarc(dmarcTxt: string[]): string | null {
  return dmarcTxt.find((t) => /^v=DMARC1\b/i.test(t.trim())) ?? null;
}

/** The enforcement level of a DMARC record: none / quarantine / reject. */
export function dmarcPolicy(record: string | null): 'none' | 'quarantine' | 'reject' | null {
  if (!record) return null;
  const m = record.match(/;\s*p\s*=\s*(none|quarantine|reject)/i);
  return m ? (m[1].toLowerCase() as 'none' | 'quarantine' | 'reject') : null;
}

/** `-all` (hard fail) or `~all` (soft fail) actually enforce; `?all`/`+all` do not. */
export function spfIsEnforcing(record: string | null): boolean {
  if (!record) return false;
  return /[-~]all\s*$/.test(record.trim());
}

const PENALTY = { high: 30, medium: 15, low: 7 } as const;

export function analyzeEmailAuth(facts: DnsFacts, host = ''): EmailAuthResult {
  const spf = findSpf(facts.txt);
  const dmarc = findDmarc(facts.dmarcTxt);
  const policy = dmarcPolicy(dmarc);

  const checks: EmailAuthCheck[] = [
    {
      key: 'spf',
      label: 'SPF record published',
      pass: !!spf,
      severity: 'high',
      detail: spf
        ? spfIsEnforcing(spf)
          ? 'published and enforcing'
          : 'published, but it ends in ?all/+all so it does not actually reject anyone'
        : 'no SPF record — anyone can send email claiming to be from this domain',
    },
    {
      key: 'dmarc',
      label: 'DMARC record published',
      pass: !!dmarc,
      severity: 'high',
      detail: dmarc
        ? `published with p=${policy ?? 'unspecified'}`
        : 'no DMARC record — nothing tells mail servers what to do with forged mail',
    },
    {
      key: 'dmarc-enforced',
      label: 'DMARC actually enforced',
      // Only meaningful once DMARC exists; p=none is monitor-only.
      pass: !dmarc ? true : policy === 'quarantine' || policy === 'reject',
      severity: 'medium',
      detail: !dmarc
        ? 'no DMARC record to enforce yet — publish one first'
        : policy === 'none'
          ? 'p=none only monitors; forged mail is still delivered'
          : `p=${policy} — forged mail is rejected or quarantined`,
    },
  ];

  const failed = checks.filter((c) => !c.pass);
  const score = Math.max(0, 100 - failed.reduce((n, c) => n + PENALTY[c.severity], 0));
  return {
    host,
    checks,
    failed,
    grade: scoreToGrade(score),
    score,
    summary:
      failed.length === 0
        ? 'Your domain is protected against email spoofing ✅'
        : `${failed.length} email-spoofing gap(s) — someone could send mail as you ⚠️`,
  };
}
