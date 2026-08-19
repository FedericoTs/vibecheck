/** Shared types for the vibecheck scan engine. */

export type Fetchy = (input: string, init?: RequestInit) => Promise<Response>;

export interface TableFinding {
  table: string;
  /** true = the anon key literally read a row from this table (a public-read leak). */
  exposed: boolean;
  /** total rows the anon role can see (from the PostgREST count header), when known. */
  rowsVisible: number | null;
  error?: string;
}

export interface SupabaseScanResult {
  ok: boolean;
  /** hostname of the Supabase project (never the key). */
  host: string;
  tablesFound: number;
  findings: TableFinding[];
  exposedCount: number;
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
