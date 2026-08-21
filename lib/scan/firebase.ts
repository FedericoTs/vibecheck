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
  /** Which Firestore database this was read from. Rules deploy PER DATABASE. */
  database: string;
  exposed: boolean;
  docsVisible: number | null;
  /**
   * The request that proved it, without the web API key — that key is public by
   * design, but it is still the user's value, so it stays a placeholder in
   * anything we render. Same rule the Supabase probe follows.
   */
  probeUrl?: string;
}

export interface FirebaseScanResult {
  ok: boolean;
  projectId: string;
  /** the whole Realtime Database is world-readable — catastrophic and common. */
  rtdbOpen: boolean;
  rtdbChecked: boolean;
  collections: FirebaseCollectionFinding[];
  /** Every Firestore database we probed, not just "(default)". */
  databases: string[];
  /**
   * True when the collection names were GUESSED rather than read from the app's
   * own bundle. A clean sweep over ten guesses is not evidence of a locked-down
   * project — it is evidence that we guessed wrong — so it must never render as
   * a pass. Unknown is a first-class outcome.
   */
  collectionsGuessed: boolean;
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

/**
 * Named Firestore databases the app references.
 *
 * Security rules are deployed PER DATABASE. A project can be correctly locked
 * down on "(default)" and wide open on "prod", and probing only the default —
 * which is all this scanner used to do — renders that project clean. That is a
 * false pass on the most serious check we run.
 */
export function extractDatabases(text: string): string[] {
  const out = new Set<string>();
  // getFirestore(app, 'name') and initializeFirestore(app, {...}, 'name')
  for (const m of text.matchAll(/\b(?:get|initialize)Firestore\s*\([^)]*?["'`]([A-Za-z0-9][\w-]{0,62})["'`]\s*\)/g)) {
    if (m[1] !== 'default') out.add(m[1]);
  }
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
  /** Named databases beyond "(default)", from extractDatabases(). */
  databases?: string[];
  fetch?: Fetchy;
}

export async function scanFirebase(opts: FirebaseScanOpts): Promise<FirebaseScanResult> {
  const fetchy = opts.fetch ?? (globalThis.fetch as Fetchy);
  const { projectId, apiKey } = opts.config;
  const named = opts.collections?.length ? opts.collections : [];
  const collectionsGuessed = named.length === 0;
  const names = (collectionsGuessed ? COMMON_COLLECTIONS : named).slice(0, 12);
  // Always probe "(default)"; add any named database the bundle referenced.
  const databases = ['(default)', ...(opts.databases ?? []).filter((d) => d && d !== '(default)')].slice(0, 4);

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
  const targets = databases.flatMap((database) => names.map((collection) => ({ database, collection })));
  const collections = await mapLimit(targets, 5, async ({ database, collection }): Promise<FirebaseCollectionFinding> => {
    const q = new URLSearchParams({ pageSize: '1' });
    if (apiKey) q.set('key', apiKey);
    const base = `https://firestore.googleapis.com/v1/projects/${encodeURIComponent(projectId)}/databases/${encodeURIComponent(database)}/documents/${encodeURIComponent(collection)}`;
    // Kept separately from the request URL so the rendered command never
    // carries the user's key, only a placeholder.
    const probeUrl = `${base}?pageSize=1`;
    try {
      const res = await fetchy(`${base}?${q}`);
      let body: unknown = null;
      try {
        body = await res.json();
      } catch {
        /* non-JSON */
      }
      const n = firestoreDocs(res.status, body);
      const exposed = (n ?? 0) > 0;
      return { collection, database, exposed, docsVisible: n, ...(exposed ? { probeUrl } : {}) };
    } catch {
      return { collection, database, exposed: false, docsVisible: null };
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
    databases,
    collectionsGuessed,
    exposedCount,
    grade,
    summary: rtdbOpen
      ? 'Your entire Realtime Database is readable by anyone ⚠️'
      : exposedCount > 0
        ? `${exposedCount} Firestore collection(s) readable by anyone ⚠️`
        : 'No Firebase data readable by anonymous visitors ✅',
  };
}
