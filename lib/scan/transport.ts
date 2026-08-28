import type { Grade } from './types';
import { scoreToGrade } from './grade';
import type { TakeoverFinding } from './takeover';

/**
 * HTTPS, certificate health, and redirect handling.
 *
 * Managed hosts renew certificates automatically, so these pass quietly for most
 * vibe-coded apps — which is the point: the check only speaks up for the people
 * it applies to, namely anyone on a custom domain or self-managed TLS, where an
 * expired certificate takes the whole app down with a browser warning.
 *
 * The open-redirect probe is the more interesting one. `/?next=https://evil.com`
 * that actually redirects turns the app's own domain into a phishing springboard:
 * the victim sees a real, trusted link. It is also the check most likely to cry
 * wolf, so it only fires when the app genuinely issues a redirect to the exact
 * foreign host we supplied — a redirect back to its own domain is correct
 * behaviour and passes.
 */

export interface TransportCheck {
  key: string;
  label: string;
  pass: boolean;
  severity: 'high' | 'medium' | 'low';
  detail?: string;
}

export interface TransportResult {
  host: string;
  checks: TransportCheck[];
  failed: TransportCheck[];
  grade: Grade;
  score: number;
  summary: string;
}

export interface CertFacts {
  checked: boolean;
  /** ISO or Date-parseable expiry from the peer certificate. */
  validTo?: string;
  issuer?: string;
  /** hostnames the certificate is valid for (CN + SANs). */
  names?: string[];
  /** the protocol a modern client negotiated, e.g. "TLSv1.3". */
  protocol?: string;
  /** did a forced TLS 1.0/1.1 handshake succeed? true = server accepts deprecated TLS. */
  allowsLegacyTls?: boolean;
}

/** Days until the certificate expires; negative once it already has. */
export function daysUntilExpiry(validTo: string | undefined, now: number): number | null {
  if (!validTo) return null;
  const t = Date.parse(validTo);
  if (!Number.isFinite(t)) return null;
  return Math.floor((t - now) / 86_400_000);
}

/** Does the certificate actually cover this hostname (incl. wildcards)? */
export function certCoversHost(names: string[] | undefined, host: string): boolean {
  if (!names || names.length === 0) return true; // unknown -> don't accuse
  const h = host.toLowerCase();
  return names.some((raw) => {
    const n = raw.toLowerCase().trim();
    if (n === h) return true;
    if (n.startsWith('*.')) {
      const suffix = n.slice(1); // ".example.com"
      // A wildcard covers exactly one label, so a.b.example.com is NOT covered by *.example.com
      return h.endsWith(suffix) && !h.slice(0, h.length - suffix.length).includes('.');
    }
    return false;
  });
}

/**
 * Did the app redirect us to the foreign host we planted? Redirecting to its own
 * domain, or not redirecting at all, is fine.
 */
export function isOpenRedirect(status: number, location: string | null, canaryHost: string): boolean {
  if (!location) return false;
  if (status < 300 || status >= 400) return false;
  try {
    // Protocol-relative (//evil.com) and absolute URLs both need catching.
    const u = new URL(location.startsWith('//') ? `https:${location}` : location, 'https://placeholder.invalid');
    return u.hostname.toLowerCase() === canaryHost.toLowerCase();
  } catch {
    return false;
  }
}

export interface TransportFacts {
  cert: CertFacts;
  /** did plain http:// redirect to https://? undefined = could not test. */
  httpsEnforced?: boolean;
  /**
   * What http:// actually did, when we could tell. A site that 301s to another
   * http URL is not the same as one that serves the page over plain http, and
   * calling both "served without redirecting" was simply wrong about the first.
   */
  httpBehaviour?: 'https' | 'http-redirect' | 'plain';
  /** query params that redirected off-site, e.g. ['next', 'redirect']. */
  openRedirectParams: string[];
  redirectChecked: boolean;
  takeover?: TakeoverFinding;
}

const PENALTY = { high: 35, medium: 15, low: 7 } as const;

export function analyzeTransport(facts: TransportFacts, host: string, now = Date.now()): TransportResult {
  const days = daysUntilExpiry(facts.cert.validTo, now);
  const checks: TransportCheck[] = [];

  if (facts.cert.checked) {
    checks.push({
      key: 'cert-expiry',
      label: 'Certificate is current',
      pass: days === null ? true : days > 0,
      severity: 'high',
      detail:
        days === null
          ? 'expiry could not be read'
          : days < 0
            ? `expired ${Math.abs(days)} day(s) ago — visitors get a full-page browser warning`
            : days <= 14
              ? `expires in ${days} day(s) — renew now`
              : `valid for another ${days} days${facts.cert.issuer ? ` (${facts.cert.issuer})` : ''}`,
    });
    // A near-expiry warning that does not fail you, but is worth seeing.
    if (days !== null && days > 0 && days <= 14) {
      checks.push({
        key: 'cert-renewal',
        label: 'Certificate renewal not urgent',
        pass: false,
        severity: 'medium',
        detail: `only ${days} day(s) left; if renewal is manual, do it now`,
      });
    }
    if (facts.cert.allowsLegacyTls !== undefined) {
      checks.push({
        key: 'tls-version',
        label: 'No deprecated TLS (1.0 / 1.1)',
        pass: !facts.cert.allowsLegacyTls,
        severity: 'medium',
        detail: facts.cert.allowsLegacyTls
          ? 'the server still accepts TLS 1.0 / 1.1 — both are deprecated and disabled in modern browsers'
          : `modern TLS only${facts.cert.protocol ? ` (this visit negotiated ${facts.cert.protocol})` : ''}`,
      });
    }
    checks.push({
      key: 'cert-host',
      label: 'Certificate matches this domain',
      pass: certCoversHost(facts.cert.names, host),
      severity: 'high',
      detail: certCoversHost(facts.cert.names, host)
        ? 'issued for this hostname'
        : `issued for ${(facts.cert.names ?? []).slice(0, 2).join(', ')} — not ${host}`,
    });
  }

  if (facts.httpsEnforced !== undefined) {
    // Three different things were being described by one sentence. Redirecting
    // to another http URL is a real finding, but it is not "served without
    // redirecting", and a report that misdescribes what it observed is worth
    // less than one that says nothing.
    const behaviour =
      facts.httpBehaviour ?? (facts.httpsEnforced ? 'https' : 'plain');
    const detail =
      behaviour === 'https'
        ? 'http requests are redirected to https'
        : behaviour === 'http-redirect'
          ? 'http redirects, but to another http address — the hop is still in the clear. Browsers that have this domain in their HSTS preload list upgrade it anyway, which we cannot see from out here.'
          : 'the page is served over plain http — traffic can be read or modified in transit';
    checks.push({
      key: 'https-enforced',
      label: 'Plain http redirects to https',
      pass: facts.httpsEnforced,
      severity: 'medium',
      detail,
    });
  }

  if (facts.redirectChecked) {
    const open = facts.openRedirectParams;
    checks.push({
      key: 'open-redirect',
      label: 'No open redirect',
      pass: open.length === 0,
      severity: 'high',
      detail:
        open.length === 0
          ? 'redirect parameters do not send visitors off-site'
          : `?${open.join('/?')} sends visitors to any site an attacker names — a phishing link that looks like yours`,
    });
  }

  // Subdomain takeover: only reported when there is something to say.
  if (facts.takeover && facts.takeover.verdict !== 'not-applicable') {
    const t = facts.takeover;
    checks.push({
      key: 'subdomain-takeover',
      label: 'Domain cannot be hijacked (no dangling CNAME)',
      pass: t.verdict === 'safe',
      severity: 'high',
      detail: t.detail,
    });
  }

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
        ? 'HTTPS, certificate and redirects all look right ✅'
        : `${failed.length} transport issue(s) ⚠️`,
  };
}
