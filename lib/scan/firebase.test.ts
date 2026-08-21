import { describe, it, expect } from 'vitest';
import {
  discoverFirebase,
  extractCollections,
  extractDatabases,
  isRtdbOpen,
  firestoreDocs,
  gradeFirebase,
  scanFirebase,
  firebaseConfigFromText,
} from './firebase';
import type { Fetchy } from './types';

const BUNDLE = `
  const firebaseConfig = {
    apiKey: "AIzaSyA1234567890abcdefghijklmnopqrstuv",
    authDomain: "my-cool-app.firebaseapp.com",
    projectId: "my-cool-app",
    storageBucket: "my-cool-app.appspot.com"
  };
  initializeApp(firebaseConfig);
  const q = collection(db, "users");
  getDocs(collection(db, "orders"));
`;

describe('discoverFirebase', () => {
  it('extracts projectId, apiKey and bucket from a real-looking config', () => {
    expect(discoverFirebase(BUNDLE)).toEqual({
      projectId: 'my-cool-app',
      apiKey: 'AIzaSyA1234567890abcdefghijklmnopqrstuv',
      storageBucket: 'my-cool-app.appspot.com',
    });
  });

  it('falls back to the authDomain when projectId is absent', () => {
    const t = 'authDomain:"fallback-app.firebaseapp.com", initializeApp(x)';
    expect(discoverFirebase(t)?.projectId).toBe('fallback-app');
  });

  it('does NOT invent a project from an unrelated projectId (no Firebase evidence)', () => {
    expect(discoverFirebase('const cfg = { projectId: "some-gcp-thing" };')).toBe(null);
  });

  it('returns null for a page with no Firebase at all', () => {
    expect(discoverFirebase('<html>hello</html>')).toBe(null);
  });
});

describe('extractCollections', () => {
  it('reads the collection names the app itself uses (modular + legacy APIs)', () => {
    expect(extractCollections(BUNDLE).sort()).toEqual(['orders', 'users']);
    expect(extractCollections('db.collection("legacy_items")')).toEqual(['legacy_items']);
  });
  it('returns nothing when the bundle names none', () => {
    expect(extractCollections('const x = 1;')).toEqual([]);
  });
});

describe('verdicts', () => {
  it('isRtdbOpen: data back = open; null/empty/denied = not open', () => {
    expect(isRtdbOpen(200, { users: true })).toBe(true);
    expect(isRtdbOpen(200, null)).toBe(false); // rules deny -> null
    expect(isRtdbOpen(200, {})).toBe(false); // empty database
    expect(isRtdbOpen(401, { users: true })).toBe(false); // blocked
  });

  it('firestoreDocs counts returned documents, null when blocked', () => {
    expect(firestoreDocs(200, { documents: [{ name: 'a' }] })).toBe(1);
    expect(firestoreDocs(200, {})).toBe(null); // permission denied returns no documents key
    expect(firestoreDocs(403, { documents: [{}] })).toBe(null);
  });

  it('gradeFirebase: open RTDB is an instant F', () => {
    expect(gradeFirebase(true, 0)).toBe('F');
    expect(gradeFirebase(false, 2)).toBe('F');
    expect(gradeFirebase(false, 1)).toBe('D');
    expect(gradeFirebase(false, 0)).toBe('A');
  });
});

// ── end-to-end with a mocked Firebase ────────────────────────────────
function res(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}
function mockFetch(routes: Array<[string, () => Response]>): Fetchy {
  return async (url) => {
    for (const [needle, make] of routes) if (url.includes(needle)) return make();
    return res({}, 404);
  };
}

describe('scanFirebase', () => {
  it('flags a wide-open Realtime Database', async () => {
    const fetchy = mockFetch([
      ['firebaseio.com', () => res({ users: { u1: { email: 'a@b.c' } } })],
      ['firestore.googleapis.com', () => res({})],
    ]);
    const r = await scanFirebase({ config: { projectId: 'my-cool-app' }, collections: ['users'], fetch: fetchy });
    expect(r.rtdbOpen).toBe(true);
    expect(r.grade).toBe('F');
    expect(r.summary).toMatch(/entire Realtime Database/);
  });

  it('flags readable Firestore collections', async () => {
    const fetchy = mockFetch([
      ['firebaseio.com', () => res(null)], // rules deny
      ['documents/users', () => res({ documents: [{ name: 'projects/x/users/1' }] })],
      ['documents/orders', () => res({})], // denied
    ]);
    const r = await scanFirebase({ config: { projectId: 'app' }, collections: ['users', 'orders'], fetch: fetchy });
    expect(r.rtdbOpen).toBe(false);
    expect(r.exposedCount).toBe(1);
    expect(r.collections.find((c) => c.collection === 'users')?.exposed).toBe(true);
    expect(r.grade).toBe('D');
  });

  it('a properly locked-down project passes', async () => {
    const fetchy = mockFetch([
      ['firebaseio.com', () => res(null)],
      ['firestore.googleapis.com', () => res({ error: { status: 'PERMISSION_DENIED' } }, 403)],
    ]);
    const r = await scanFirebase({ config: { projectId: 'app' }, collections: ['users'], fetch: fetchy });
    expect(r.exposedCount).toBe(0);
    expect(r.grade).toBe('A');
    expect(r.summary).toMatch(/No Firebase data readable/);
  });
});

describe('firebaseConfigFromText — manual paste (mobile apps)', () => {
  it('takes a pasted config at face value, no corroboration guard', () => {
    // A bare config that discoverFirebase would REJECT (no firebaseapp.com etc.)
    const bare = 'projectId: "my-mobile-app", apiKey: "AIzaSyA1234567890abcdefghijklmnopqrstuv"';
    expect(discoverFirebase(bare)).toBe(null); // auto-detect refuses it
    const manual = firebaseConfigFromText(bare); // manual accepts it
    expect(manual?.projectId).toBe('my-mobile-app');
    expect(manual?.apiKey).toBe('AIzaSyA1234567890abcdefghijklmnopqrstuv');
  });

  it('returns null when there is no project id to work with', () => {
    expect(firebaseConfigFromText('just some text')).toBe(null);
  });
});

describe('named Firestore databases', () => {
  it('finds the databases the bundle references, ignoring the default', () => {
    expect(extractDatabases("const db = getFirestore(app, 'prod');")).toEqual(['prod']);
    expect(extractDatabases('initializeFirestore(app, {}, "analytics-eu")')).toEqual(['analytics-eu']);
    expect(extractDatabases("getFirestore(app, 'default')")).toEqual([]);
    expect(extractDatabases('getFirestore(app)')).toEqual([]);
  });

  /**
   * The false PASS this fixes: rules deploy per database, so a project locked
   * down on "(default)" and wide open on "prod" used to render clean.
   */
  it('probes every named database, not just the default', async () => {
    const seen: string[] = [];
    const fetchy = async (url: string) => {
      seen.push(url);
      const open = url.includes('/databases/prod/');
      return {
        status: 200,
        json: async () => (open ? { documents: [{ name: 'x' }] } : {}),
      } as unknown as Response;
    };
    const r = await scanFirebase({
      config: { projectId: 'app' },
      collections: ['users'],
      databases: ['prod'],
      fetch: fetchy as never,
    });
    expect(r.databases).toEqual(['(default)', 'prod']);
    expect(seen.some((u) => u.includes('/databases/(default)/'))).toBe(true);
    expect(seen.some((u) => u.includes('/databases/prod/'))).toBe(true);
    // The locked default must not mask the open named database.
    expect(r.exposedCount).toBe(1);
    expect(r.collections.find((c) => c.exposed)?.database).toBe('prod');
  });

  it('carries a probe URL on an exposed collection, and never on a locked one', async () => {
    const fetchy = async (url: string) =>
      ({ status: 200, json: async () => (url.includes('users') ? { documents: [{ name: 'x' }] } : {}) }) as unknown as Response;
    const r = await scanFirebase({
      config: { projectId: 'app', apiKey: 'AIza-secret-value' },
      collections: ['users', 'locked'],
      fetch: fetchy as never,
    });
    const exposed = r.collections.find((c) => c.collection === 'users')!;
    const locked = r.collections.find((c) => c.collection === 'locked')!;
    expect(exposed.probeUrl).toContain('/databases/(default)/documents/users');
    expect(locked.probeUrl).toBeUndefined();
    // The user's key must never be baked into anything we render.
    expect(exposed.probeUrl).not.toContain('AIza-secret-value');
  });

  it('marks collection names as guessed when the bundle names none', async () => {
    const fetchy = async () => ({ status: 403, json: async () => ({}) }) as unknown as Response;
    const guessed = await scanFirebase({ config: { projectId: 'app' }, fetch: fetchy as never });
    expect(guessed.collectionsGuessed).toBe(true);

    const known = await scanFirebase({ config: { projectId: 'app' }, collections: ['orders'], fetch: fetchy as never });
    expect(known.collectionsGuessed).toBe(false);
  });
});
