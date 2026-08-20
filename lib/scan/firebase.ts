import type { Fetchy, Grade } from './types';
import { scoreToGrade } from './grade';

/**
 * Firebase exposure scanner — the Firestore/RTDB equivalent of the Supabase RLS
 * check, and the other half of the vibe-coded app world (Bolt and v0 lean
 * Firebase where Lovable leans Supabase).
 *
 * Firebase config is public by design: it ships in every Firebase web app's
 * bundle. What is NOT meant to be public is the *data* behind it. An app
 * generated with `allow read: if true` serves its entire database to anyone
 * holding that public config — which is exactly what this checks, read-only,
 * from the visitor's own browser.
 */

export interface FirebaseConfig {
  projectId: string;
  apiKey?: string;
  storageBucket?: string;
}

export interface FirebaseCollectionFinding {
  collection: string;
  exposed: boolean;
  docsVisible: number | null;
}

export interface FirebaseScanResult {
  ok: boolean;
  projectId: string;
  /** the whole Realtime Database is world-readable — catastrophic and common. */
  rtdbOpen: boolean;
  rtdbChecked: boolean;
  collections: FirebaseCollectionFinding[];
  exposedCount: number;
  grade: Grade;
  summary: string;
  error?: string;
}

// ── discovery (pure) ─────────────────────────────────────────────────

const PROJECT_ID = /["'`]?projectId["'`]?\s*[:=]\s*["'`]([a-z0-9-]{4,40})["'`]/i;
const API_KEY = /["'`]?apiKey["'`]?\s*[:=]\s*["'`](AIza[0-9A-Za-z_-]{35})["'`]/;
const STORAGE_BUCKET = /["'`]?storageBucket["'`]?\s*[:=]\s*["'`]([a-z0-9.-]+\.(?:appspot\.com|firebasestorage\.app))["'`]/i;
const AUTH_DOMAIN = /([a-z0-9-]{4,40})\.firebaseapp\.com/i;

/** Find the Firebase project a site exposes in its own frontend, if any. */
export function discoverFirebase(text: string): FirebaseConfig | null {
  const projectId = text.match(PROJECT_ID)?.[1] ?? text.match(AUTH_DOMAIN)?.[1];
  if (!projectId) return null;
  // Only treat it as Firebase if there's corroborating evidence, so a stray
  // "projectId" from an unrelated SDK doesn't produce a phantom scan.
  const looksFirebase = /firebaseapp\.com|firebaseio\.com|firestore|firebasestorage|initializeApp/i.test(text);
  if (!looksFirebase) return null;
  return {
    projectId,
    apiKey: text.match(API_KEY)?.[1],
    storageBucket: text.match(STORAGE_BUCKET)?.[1],
  };
}

/**
 * Lenient parse for a Firebase config the user EXPLICITLY pasted (e.g. from a
 * mobile app). discoverFirebase() applies a corroboration guard to avoid false
 * positives during an automatic web scan; here the user has said "this is my
 * Firebase config", so we take a projectId + optional apiKey/bucket at face value.
 */
export function firebaseConfigFromText(text: string): FirebaseConfig | null {
  const projectId = text.match(PROJECT_ID)?.[1] ?? text.match(AUTH_DOMAIN)?.[1];
  if (!projectId) return null;
  return {
    projectId,
    apiKey: text.match(API_KEY)?.[1],
    storageBucket: text.match(STORAGE_BUCKET)?.[1],
  };
}

/**
 * Collection names the app itself references — far better than guessing.
 * Matches the modular `collection(db, "users")` and legacy `.collection("users")`.
 */
export function extractCollections(text: string): string[] {
  const out = new Set<string>();
  for (const m of text.matchAll(/\bcollection\s*\(\s*[A-Za-z_$][\w$]*\s*,\s*["'`]([A-Za-z0-9_-]{2,40})["'`]/g)) out.add(m[1]);
  for (const m of text.matchAll(/\.collection\s*\(\s*["'`]([A-Za-z0-9_-]{2,40})["'`]/g)) out.add(m[1]);
  return [...out];
}

/** Collections worth trying when the bundle names none. */
export const COMMON_COLLECTIONS = [
  'users', 'posts', 'messages', 'orders', 'products',
  'profiles', 'items', 'todos', 'comments', 'bookings',
];

// ── verdicts (pure) ──────────────────────────────────────────────────

/** The Realtime Database root returned data without auth => wide open. */
export function isRtdbOpen(status: number, body: unknown): boolean {
  if (status !== 200) return false;
  if (body === null) return false; // empty DB, or rules deny -> null
  if (typeof body === 'object' && Object.keys(body as object).length === 0) return false;
  return true;
}

/** A Firestore REST list response that actually returned documents. */
export function firestoreDocs(status: number, body: unknown): number | null {
  if (status !== 200) return null;
  const docs = (body as { documents?: unknown[] })?.documents;
  return Array.isArray(docs) ? docs.length : null;
}

export function gradeFirebase(rtdbOpen: boolean, exposedCount: number): Grade {
  if (rtdbOpen) return 'F'; // the entire database is readable
  if (exposedCount >= 2) return 'F';
  if (exposedCount === 1) return 'D';
  return scoreToGrade(100);
}

// ── the scan ─────────────────────────────────────────────────────────

async function mapLimit<T, R>(items: T[], limit: number, fn: (t: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let i = 0;
  await Promise.all(
    Array.from({ length: Math.min(limit, items.length) }, async () => {
      while (i < items.length) {
        const idx = i++;
        out[idx] = await fn(items[idx]);
      }
    }),
  );
  return out;
}

export interface FirebaseScanOpts {
  config: FirebaseConfig;
  collections?: string[];
  fetch?: Fetchy;
}

export async function scanFirebase(opts: FirebaseScanOpts): Promise<FirebaseScanResult> {
  const fetchy = opts.fetch ?? (globalThis.fetch as Fetchy);
  const { projectId, apiKey } = opts.config;
  const names = (opts.collections?.length ? opts.collections : COMMON_COLLECTIONS).slice(0, 12);

  // 1) Realtime Database: is the root world-readable?
  let rtdbOpen = false;
  let rtdbChecked = false;
  for (const host of [`${projectId}-default-rtdb.firebaseio.com`, `${projectId}.firebaseio.com`]) {
    try {
      const res = await fetchy(`https://${host}/.json?shallow=true`);
      let body: unknown = null;
      try {
        body = await res.json();
      } catch {
        /* non-JSON */
      }
      rtdbChecked = true;
      if (isRtdbOpen(res.status, body)) {
        rtdbOpen = true;
        break;
      }
    } catch {
      /* no RTDB at this host */
    }
  }

  // 2) Firestore: can anyone list documents in the app's collections?
  const collections = await mapLimit(names, 5, async (collection): Promise<FirebaseCollectionFinding> => {
    const q = new URLSearchParams({ pageSize: '1' });
    if (apiKey) q.set('key', apiKey);
    const url = `https://firestore.googleapis.com/v1/projects/${encodeURIComponent(projectId)}/databases/(default)/documents/${encodeURIComponent(collection)}?${q}`;
    try {
      const res = await fetchy(url);
      let body: unknown = null;
      try {
        body = await res.json();
      } catch {
        /* non-JSON */
      }
      const n = firestoreDocs(res.status, body);
      return { collection, exposed: (n ?? 0) > 0, docsVisible: n };
    } catch {
      return { collection, exposed: false, docsVisible: null };
    }
  });

  const exposedCount = collections.filter((c) => c.exposed).length;
  const grade = gradeFirebase(rtdbOpen, exposedCount);

  return {
    ok: true,
    projectId,
    rtdbOpen,
    rtdbChecked,
    collections,
    exposedCount,
    grade,
    summary: rtdbOpen
      ? 'Your entire Realtime Database is readable by anyone ⚠️'
      : exposedCount > 0
        ? `${exposedCount} Firestore collection(s) readable by anyone ⚠️`
        : 'No Firebase data readable by anonymous visitors ✅',
  };
}
