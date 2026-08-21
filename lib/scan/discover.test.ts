import { describe, it, expect } from 'vitest';
import { findSupabaseUrls, findAnonKeys, discoverSupabase, findBackendPairs, isProbeableKey } from './discover';

const b64url = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
const jwt = (payload: object) => `${b64url({ alg: 'HS256', typ: 'JWT' })}.${b64url(payload)}.sigsigsig`;

const ANON = jwt({ role: 'anon', iss: 'supabase' });
const SERVICE = jwt({ role: 'service_role', iss: 'supabase' });

const BUNDLE = `
  const SUPABASE_URL="https://abcdefghijkl.supabase.co";
  const SUPABASE_ANON_KEY="${ANON}";
  createClient(SUPABASE_URL, SUPABASE_ANON_KEY);
`;

describe('findSupabaseUrls', () => {
  it('finds the project URL and normalises it', () => {
    expect(findSupabaseUrls(BUNDLE)).toEqual(['https://abcdefghijkl.supabase.co']);
  });
  it('dedupes repeats and ignores unrelated hosts', () => {
    const t = 'https://abcdefghijkl.supabase.co x https://abcdefghijkl.supabase.co y https://example.com';
    expect(findSupabaseUrls(t)).toHaveLength(1);
    expect(findSupabaseUrls('https://example.com')).toEqual([]);
  });
});

describe('findAnonKeys', () => {
  it('returns anon keys only — NEVER a service_role key', () => {
    expect(findAnonKeys(BUNDLE)).toEqual([ANON]);
    expect(findAnonKeys(`key="${SERVICE}"`)).toEqual([]);
  });
  it('ignores non-JWT junk', () => {
    expect(findAnonKeys('const x = "not.a.jwt";')).toEqual([]);
  });
});

describe('discoverSupabase', () => {
  it('pairs the URL + anon key from a real-looking bundle', () => {
    expect(discoverSupabase(BUNDLE)).toEqual({
      url: 'https://abcdefghijkl.supabase.co',
      pairing: 'supabase-host',
      anonKey: ANON,
    });
  });

  it('returns null when either half is missing', () => {
    expect(discoverSupabase('https://abcdefghijkl.supabase.co only')).toBe(null);
    expect(discoverSupabase(`key ${ANON} only`)).toBe(null);
    expect(discoverSupabase('nothing here')).toBe(null);
  });

  it('does not hand back a service_role key even when one is present', () => {
    const d = discoverSupabase(`https://abcdefghijkl.supabase.co ${SERVICE}`);
    expect(d).toBe(null); // no anon key -> nothing to probe with
  });

  it('REGRESSION: supports the CURRENT sb_publishable_ key format, not just legacy JWTs', () => {
    // Found by scanning a real production app: Supabase replaced the legacy
    // `role: anon` JWT with `sb_publishable_…`, so JWT-only discovery silently
    // missed every modern project — including the flagship database check.
    const modern = 'const u="https://abcdefghijkl.supabase.co",k="sb_publishable_' + 'A'.repeat(30) + '";';
    const d = discoverSupabase(modern);
    expect(d?.url).toBe('https://abcdefghijkl.supabase.co');
    expect(d?.anonKey).toMatch(/^sb_publishable_/);
  });

  it('never returns the privileged sb_secret_ key to probe with', () => {
    const withSecret = 'https://abcdefghijkl.supabase.co "sb_secret_' + 'B'.repeat(30) + '"';
    expect(discoverSupabase(withSecret)).toBe(null);
  });
});

describe('findBackendPairs — the exfiltration guard', () => {
  const ANON = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYW5vbiIsImlzcyI6InN1cGFiYXNlIn0.sigsigsig';

  it('supports a self-hosted or custom-domain backend when the code pairs them', () => {
    const bundle = `const supabase = createClient("https://db.mycompany.com", "${ANON}");`;
    expect(findBackendPairs(bundle)).toEqual([
      { url: 'https://db.mycompany.com', anonKey: ANON, pairing: 'create-client' },
    ]);
  });

  /**
   * The reason the loose "first URL + first key" pairing was only ever safe
   * while the host pattern was pinned to *.supabase.co. Unpinned, it would
   * post the user's credential to whatever unrelated origin happened to appear
   * first in their bundle.
   */
  it('never points a key at an unrelated origin that merely appears nearby', () => {
    const bundle = `
      const analytics = "https://api.some-third-party.com/collect";
      const cdn = "https://cdn.example.net/app.js";
      const KEY = "${ANON}";
    `;
    expect(findBackendPairs(bundle)).toEqual([]);
    expect(discoverSupabase(bundle)).toBe(null);
  });

  it('still pairs a hosted Supabase project found anywhere in the bundle', () => {
    const bundle = `
      fetch("https://api.some-third-party.com/collect");
      const url = "https://abcdefghijkl.supabase.co";
      const key = "${ANON}";
    `;
    const pairs = findBackendPairs(bundle);
    expect(pairs).toHaveLength(1);
    expect(pairs[0].url).toBe('https://abcdefghijkl.supabase.co');
    expect(pairs[0].pairing).toBe('supabase-host');
  });

  it('prefers the explicit createClient pairing over the looser one', () => {
    const bundle = `
      const url = "https://abcdefghijkl.supabase.co";
      createClient("https://db.mycompany.com", "${ANON}");
      const key = "${ANON}";
    `;
    expect(findBackendPairs(bundle)[0].pairing).toBe('create-client');
    expect(discoverSupabase(bundle)!.url).toBe('https://db.mycompany.com');
  });

  it('refuses to probe with a privileged key, however it is paired', () => {
    const secret = 'sb_secret_abcdefghijklmnopqrstuvwxyz';
    expect(isProbeableKey(secret)).toBe(false);
    expect(findBackendPairs(`createClient("https://db.mycompany.com", "${secret}")`)).toEqual([]);

    const service =
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.sigsigsig';
    expect(isProbeableKey(service)).toBe(false);
    expect(findBackendPairs(`createClient("https://db.mycompany.com", "${service}")`)).toEqual([]);
  });

  it('ignores a non-http origin', () => {
    expect(findBackendPairs(`createClient("file:///etc/passwd", "${ANON}")`)).toEqual([]);
  });
});
