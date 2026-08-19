import { describe, it, expect } from 'vitest';
import {
  discoverFirebase,
  extractCollections,
  isRtdbOpen,
  firestoreDocs,
  gradeFirebase,
  scanFirebase,
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
