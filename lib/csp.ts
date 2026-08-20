/**
 * The site's own Content-Security-Policy.
 *
 * We grade other people's CSPs, so ours has to survive our own check —
 * `cspIsMeaningful()` in lib/scan/headers.ts rejects a script-src containing
 * 'unsafe-inline', 'unsafe-eval', a bare `*` or a bare `https:`. There is a unit
 * test asserting exactly that, so the policy below cannot silently rot into
 * decoration.
 *
 * Every directive here is a deliberate decision, documented because a CSP that
 * nobody can explain gets loosened by the next person who hits a console error.
 */
export interface CspOptions {
  /** Per-request nonce, base64. Next.js applies it to the inline RSC payload scripts it emits. */
  nonce: string;
}

/** The one third-party image host on the page (the DivvLaunches featured badge). */
const BADGE_HOST = 'https://www.divvlaunches.com';

export function buildCsp({ nonce }: CspOptions): string {
  const directives: string[] = [
    `default-src 'self'`,

    // Scripts: same-origin bundles plus the per-request nonce that Next puts on
    // the inline scripts streaming the RSC payload. No 'unsafe-inline', no
    // 'unsafe-eval'.
    //
    // 'strict-dynamic' is deliberately NOT used yet. It causes CSP3 browsers to
    // ignore 'self', so every script element must carry the nonce — and we have
    // not confirmed that the injected analytics script does. Shipping a policy
    // that silently breaks a script is worse than shipping a slightly weaker one
    // that holds; revisit once that is verified in a browser.
    `script-src 'self' 'nonce-${nonce}'`,

    // Styles need 'unsafe-inline' and it is honest to say why: the report draws
    // computed values as inline style attributes (severity-bar widths, dial
    // geometry) and next/font emits an inline @font-face block. A nonce cannot
    // cover style ATTRIBUTES, and adding one here would make browsers ignore
    // 'unsafe-inline' and break the report's charts. Style injection is a far
    // smaller risk than script injection, and script-src stays strict.
    `style-src 'self' 'unsafe-inline'`,

    `img-src 'self' data: blob: ${BADGE_HOST}`,

    // next/font self-hosts at build time, so no external font origin is needed.
    `font-src 'self'`,

    // THE LOAD-BEARING ONE. The database-exposure probe runs in the visitor's
    // OWN browser against the visitor's OWN backend — that is the entire privacy
    // design, and those origins are unknowable in advance. 'self' alone would
    // break the flagship feature. Restricted to https so a scan cannot be
    // downgraded to cleartext.
    `connect-src 'self' https:`,

    // Nothing here embeds or is embedded. frame-ancestors is the modern
    // equivalent of the X-Frame-Options: DENY we also send.
    `object-src 'none'`,
    `frame-src 'none'`,
    `frame-ancestors 'none'`,

    // Stop an injected <base> from re-pointing every relative URL, and stop a
    // form from being retargeted at an attacker's collector.
    `base-uri 'self'`,
    `form-action 'self'`,

    `upgrade-insecure-requests`,
  ];

  return directives.join('; ');
}

/** 128 bits of randomness, base64 — regenerated per request. */
export function generateNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return btoa(String.fromCharCode(...bytes));
}
