import { jwtRole } from './secrets';

/**
 * Discover the Supabase project a site already exposes in its own frontend.
 *
 * Every Supabase web app ships its project URL and `anon` key in the client
 * bundle — they are public by design, readable by any visitor with devtools.
 * Finding them lets vibecheck run the database-exposure check from ONE pasted
 * URL, with no copy-pasting of keys.
 *
 * Crucially this only *locates* the project. The table probes themselves still
 * run in the visitor's own browser, so vibecheck never queries anyone's
 * database from its servers — the thing every competing scanner does.
 */

/** How we concluded that a key belongs to a particular origin. */
export type Pairing = 'create-client' | 'supabase-host';

export interface DiscoveredSupabase {
  url: string;
  anonKey: string;
  pairing: Pairing;
}

const PROJECT_URL = /https?:\/\/([a-z0-9]{8,})\.supabase\.(?:co|in)/gi;
const JWT = /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g;
// Supabase's current key format, which replaced the legacy `role: anon` JWT.
// `sb_publishable_…` is the public client key; `sb_secret_…` is the privileged
// one and must NEVER be used to probe (it is a secrets-scan finding instead).
const PUBLISHABLE = /\bsb_publishable_[A-Za-z0-9_-]{16,}/g;

/** Supabase project URLs referenced in a blob of client code. */
export function findSupabaseUrls(text: string): string[] {
  const out = new Set<string>();
  for (const m of text.matchAll(PROJECT_URL)) out.add(`https://${m[1]}.supabase.co`);
  return [...out];
}

/**
 * Anon keys (JWTs whose role claim is `anon`) in a blob of client code.
 * A `service_role` key is deliberately NOT returned here — that is a finding
 * for the secrets scan, never something to go querying with.
 */
export function findAnonKeys(text: string): string[] {
  const out = new Set<string>();
  // Current format first — new projects ship these instead of a JWT.
  for (const m of text.matchAll(PUBLISHABLE)) out.add(m[0]);
  for (const m of text.matchAll(JWT)) {
    if (jwtRole(m[0]) === 'anon') out.add(m[0]);
  }
  return [...out];
}

/**
 * `createClient(url, key)` — the app itself stating which origin the key is for.
 *
 * This is the ONLY evidence strong enough to point a key at an origin we do not
 * otherwise recognise, and it is what makes self-hosted and custom-domain
 * PostgREST safe to support.
 */
const CREATE_CLIENT =
  /createClient\s*\(\s*["'`](https?:\/\/[^"'`\s)]+)["'`]\s*,\s*["'`]([A-Za-z0-9._-]{20,})["'`]/g;

/** Is this a key we are allowed to probe with? Never a secret or service_role one. */
export function isProbeableKey(key: string): boolean {
  if (/^sb_secret_/.test(key)) return false;
  if (/^sb_publishable_[A-Za-z0-9_-]{16,}$/.test(key)) return true;
  return jwtRole(key) === 'anon';
}

/** The scheme + host of a URL, or null if it is not a plain http(s) URL. */
function safeOrigin(raw: string): string | null {
  try {
    const u = new URL(raw);
    if (u.protocol !== 'https:' && u.protocol !== 'http:') return null;
    return u.origin;
  } catch {
    return null;
  }
}

/**
 * Every (origin, key) pair the bundle actually supports, most-trustworthy first.
 *
 * ⚠️ THE SAFETY RULE THIS ENFORCES ⚠️
 * A bundle routinely references many origins — analytics, a CDN, third-party
 * APIs. Taking "the first URL" and "the first key" and pairing them, which is
 * what this module used to do, is only safe while the URL pattern is pinned to
 * `*.supabase.co`: the blast radius is a Supabase host, and a Supabase key can
 * only be for a Supabase project. The moment arbitrary origins are allowed,
 * that same logic would send the user's credential to whatever unrelated host
 * happened to appear first in their bundle. That is not a scan, it is
 * exfiltration, and we would be doing it on their behalf.
 *
 * So an origin we do not recognise is only ever paired with a key when the code
 * itself put them together in one `createClient(url, key)` call.
 */
export function findBackendPairs(text: string): DiscoveredSupabase[] {
  const out: DiscoveredSupabase[] = [];
  const seen = new Set<string>();
  const push = (rawUrl: string, anonKey: string, pairing: Pairing): void => {
    const url = safeOrigin(rawUrl);
    if (!url || !isProbeableKey(anonKey)) return;
    const id = `${url}|${anonKey}`;
    if (seen.has(id)) return;
    seen.add(id);
    out.push({ url, anonKey, pairing });
  };

  // 1. The app told us, in one expression. Works for any host.
  for (const m of text.matchAll(CREATE_CLIENT)) push(m[1], m[2], 'create-client');

  // 2. A *.supabase.co origin. The host itself bounds the risk, so the looser
  //    "both appear in this bundle" pairing stays acceptable here.
  const hosted = findSupabaseUrls(text)[0];
  const key = findAnonKeys(text)[0];
  if (hosted && key) push(hosted, key, 'supabase-host');

  return out;
}

/** Pair a project URL with an anon key, if the page exposes both. */
export function discoverSupabase(text: string): DiscoveredSupabase | null {
  return findBackendPairs(text)[0] ?? null;
}
