/** Shared types for the vibecheck scan engine. */

export type Fetchy = (input: string, init?: RequestInit) => Promise<Response>;

export interface TableFinding {
  /** Column names visible to anonymous readers. NAMES ONLY — never any values. */
  columns?: string[];
  table: string;
  /** true = the anon key literally read a row from this table (a public-read leak). */
  exposed: boolean;
  /** total rows the anon role can see (from the PostgREST count header), when known. */
  rowsVisible: number | null;
  /**
   * The literal request that proved it — so the finding is reproducible rather
   * than asserted. Contains no credential: the anon key travels as a header,
   * and it is the user's own public key in any case. Never leaves the browser.
   */
  probeUrl?: string;
  error?: string;
}

export interface BucketFinding {
  /** anon could enumerate the project's storage buckets at all. */
  enumerable: boolean;
  /** names of buckets marked public (readable by anyone). */
  publicBuckets: string[];
  checked: boolean;
}

export interface AuthConfigFinding {
  checked: boolean;
  /** anyone can create an account (often fine, but it compounds autoConfirm). */
  signupsOpen: boolean;
  /** accounts are usable WITHOUT proving the email address belongs to them. */
  autoConfirm: boolean;
  providers: string[];
}

export interface RpcFinding {
  /** database functions PostgREST exposes to the public API surface. */
  exposed: string[];
  checked: boolean;
}

export interface SupabaseScanResult {
  ok: boolean;
  /** hostname of the Supabase project (never the key). */
  host: string;
  tablesFound: number;
  findings: TableFinding[];
  exposedCount: number;
  buckets?: BucketFinding;
  rpc?: RpcFinding;
  auth?: AuthConfigFinding;
  grade: Grade;
  /** a human summary line, safe to show and share. */
  summary: string;
  error?: string;
}

export type Grade = 'A' | 'B' | 'C' | 'D' | 'F';

export interface GradeResult {
  grade: Grade;
  score: number; // 0-100
  label: string;
}
