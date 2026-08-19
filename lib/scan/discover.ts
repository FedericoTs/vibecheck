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

export interface DiscoveredSupabase {
  url: string;
  anonKey: string;
}

const PROJECT_URL = /https?:\/\/([a-z0-9]{8,})\.supabase\.(?:co|in)/gi;
const JWT = /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g;

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
  for (const m of text.matchAll(JWT)) {
    if (jwtRole(m[0]) === 'anon') out.add(m[0]);
  }
  return [...out];
}

/** Pair a project URL with an anon key, if the page exposes both. */
export function discoverSupabase(text: string): DiscoveredSupabase | null {
  const url = findSupabaseUrls(text)[0];
  const anonKey = findAnonKeys(text)[0];
  return url && anonKey ? { url, anonKey } : null;
}
